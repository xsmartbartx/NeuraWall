"""Linked mode: the plan comes from NEXORA (pull), never the other way round, and a billing
or network problem can never change what the firewall enforces."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import service as service_module
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")
ORG = "org_acme"
KEY = "nx_live_secret_value_123"


class FakeNexora:
    """A stand-in for api.onenexora.com that records what the installation sends."""

    def __init__(self):
        self.plan = "pro"
        self.org = ORG
        self.period_end = None
        self.status = 200
        self.down = False
        self.requests: list[httpx.Request] = []
        self.events: list[dict] = []
        self.events_status = 202

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("unreachable")
        if request.url.path == "/v1/events":
            if self.events_status >= 400:
                return httpx.Response(self.events_status, json={"error": "x"})
            self.events += json.loads(request.content)["events"]
            return httpx.Response(self.events_status, json={"stored": True})
        if self.status != 200:
            return httpx.Response(self.status, json={"error": "x"})
        return httpx.Response(
            200,
            json={
                "org_id": self.org,
                "plan_id": self.plan,
                "current_period_end": self.period_end,
            },
        )


def make(tmp_path, handler, **overrides):
    cfg = {
        "environment": "test",
        "data_dir": tmp_path,
        "log_json": False,
        "auth": {"bootstrap_admin_password": ADMIN[1], "sso_required_org_id": ORG},
        "nexora": {"api_key": KEY},
        **overrides,
    }
    settings = load_settings(**cfg)
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    cp._nexora_transport = httpx.MockTransport(handler)
    client = TestClient(create_app(settings, control_plane=cp, start_background=False))
    return cp, client


@pytest.fixture
def nexora():
    return FakeNexora()


@pytest.fixture
def linked(tmp_path, nexora):
    cp, client = make(tmp_path, nexora)
    with client as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}, nexora


def test_standalone_installs_are_untouched(tmp_path):
    settings = load_settings(
        environment="test", data_dir=tmp_path, auth={"bootstrap_admin_password": ADMIN[1]}
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        h = {
            "Authorization": "Bearer "
            + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()[
                "access_token"
            ]
        }
        assert c.get("/api/v1/nexora/status", headers=h).json()["linked"] is False
        assert c.post("/api/v1/nexora/sync", headers=h).status_code == 404
        assert c.get("/api/v1/billing", headers=h).json()["linked"] is False
    assert not any(t.name == "nexora-sync" for t in cp._threads)


def test_a_sync_applies_the_plan_and_calls_nexora_with_the_key(linked):
    cp, c, h, fake = linked
    assert cp.plan().plan_id.value == "community"  # nothing pulled yet
    out = c.post("/api/v1/nexora/sync", headers=h).json()
    assert out["plan"] == "pro" and out["error"] is None and out["last_ok"]
    assert cp.plan().nodes_limit == 5
    req = fake.requests[-1]
    assert req.method == "GET" and req.url.path == "/v1/entitlements/neurawall"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    billing = c.get("/api/v1/billing", headers=h).json()
    assert billing["source"] == "nexora" and billing["linked"] is True
    assert billing["manage_url"] == "https://console.onenexora.com/billing"
    assert billing["self_serve"] is False
    assert all(not any(p["purchasable"].values()) for p in billing["plans"])
    actions = [e["action"] for e in c.get("/api/v1/audit", headers=h).json()["items"]]
    assert "billing.nexora_plan_changed" in actions


def test_the_api_key_is_never_returned(linked):
    _, c, h, _ = linked
    c.post("/api/v1/nexora/sync", headers=h)
    for path in ("/api/v1/nexora/status", "/api/v1/billing", "/api/v1/system"):
        assert KEY not in c.get(path, headers=h).text


def test_local_checkout_and_portal_are_refused_when_linked(linked):
    _, c, h, _ = linked
    for path, body in (
        ("/api/v1/billing/checkout", {"plan": "pro", "interval": "month"}),
        ("/api/v1/billing/portal", None),
    ):
        r = c.post(path, headers=h, json=body)
        assert r.status_code == 403
        assert "managed in NEXORA" in r.text


def test_a_local_stripe_row_cannot_compete_with_nexora(linked):
    cp, c, h, fake = linked
    fake.plan = "community"
    c.post("/api/v1/nexora/sync", headers=h)
    with cp.db.session() as s:
        s.add(
            service_module.db.Subscription(
                provider="stripe",
                provider_subscription_id="sub_old",
                plan_id="enterprise",
                status="active",
                current_period_end=None,
            )
        )
    assert cp.plan().plan_id.value == "community"


def test_a_key_for_another_organisation_is_refused(linked):
    cp, c, h, fake = linked
    fake.org = "org_someone_else"
    out = c.post("/api/v1/nexora/sync", headers=h).json()
    assert "different organisation" in out["error"]
    assert cp.plan().plan_id.value == "community"


@pytest.mark.parametrize("status", [401, 403, 500])
def test_nexora_errors_are_recorded_not_raised(linked, status):
    cp, c, h, fake = linked
    fake.status = status
    r = c.post("/api/v1/nexora/sync", headers=h)
    assert r.status_code == 200 and r.json()["error"]
    assert cp.plan().plan_id.value == "community"


def test_an_unreadable_answer_is_an_error(tmp_path):
    cp, client = make(tmp_path, lambda req: httpx.Response(200, json={"plan_id": 7}))
    with client:
        assert "unreadable" in cp.sync_nexora()["error"]


def test_the_plan_survives_an_outage_then_lapses(linked, monkeypatch):
    cp, c, h, fake = linked
    c.post("/api/v1/nexora/sync", headers=h)
    assert cp.plan().plan_id.value == "pro"
    fake.down = True
    out = c.post("/api/v1/nexora/sync", headers=h).json()
    assert out["error"] == "NEXORA is unreachable" and cp.plan().plan_id.value == "pro"
    # Valid for 4 days after the last good sync, plus 3 days of grace.
    real = service_module.time.time
    monkeypatch.setattr(service_module.time, "time", lambda: real() + 6.5 * 86400)
    assert cp.plan().plan_id.value == "pro"
    monkeypatch.setattr(service_module.time, "time", lambda: real() + 7.5 * 86400)
    assert cp.plan().plan_id.value == "community"


def test_the_period_end_from_nexora_caps_validity(linked):
    _, c, h, fake = linked
    real = service_module.time.time()
    fake.period_end = int(real + 3600)
    c.post("/api/v1/nexora/sync", headers=h)
    status = c.get("/api/v1/nexora/status", headers=h).json()
    assert abs(status["plan_valid_until"] - (real + 3600)) < 5


def test_a_downgrade_never_changes_what_nodes_enforce(linked):
    cp, c, h, fake = linked
    c.post("/api/v1/nexora/sync", headers=h)

    def enroll(name):
        token = c.post("/api/v1/nodes/enrollment-tokens", headers=h, json={}).json()["token"]
        return c.post("/api/v1/agent/enroll", json={"token": token, "name": name})

    keys = []
    for n in range(3):
        r = enroll(f"edge-{n}")
        assert r.status_code == 201, r.text
        keys.append({"Authorization": f"Bearer {r.json()['api_key']}"})

    fake.plan = "community"  # the organisation cancelled: 3 nodes on a 1-node plan
    c.post("/api/v1/nexora/sync", headers=h)
    assert cp.plan().plan_id.value == "community"

    gen = TrafficGenerator(seed=5)
    flows = [f.model_dump(mode="json") for f in gen.scenario("command_injection", 10)]
    for nh in keys:  # every enrolled node keeps working
        assert c.get("/api/v1/agent/bundle", headers=nh).status_code == 200
        assert (
            c.post(
                "/api/v1/agent/heartbeat",
                headers=nh,
                json={"applied_version": 1, "backend": "dry-run", "stats": {}},
            ).status_code
            == 200
        )
        assert c.post("/api/v1/agent/flows", headers=nh, json={"flows": flows}).status_code == 200
    # ... but no further node can be enrolled.
    assert enroll("edge-9").status_code == 403


def test_manual_sync_is_rate_limited(linked):
    _, c, h, _ = linked
    codes = [c.post("/api/v1/nexora/sync", headers=h).status_code for _ in range(7)]
    assert codes == [200] * 6 + [403]


def test_only_admins_see_the_link(linked):
    _, c, h, _ = linked
    c.post(
        "/api/v1/users",
        headers=h,
        json={
            "email": "v@example.com",
            "name": "V",
            "role": "operator",
            "password": "Viewer-Pass-1!x",
        },
    )
    t = c.post("/api/v1/auth/login", json={"email": "v@example.com", "password": "Viewer-Pass-1!x"})
    vh = {"Authorization": f"Bearer {t.json()['access_token']}"}
    assert c.get("/api/v1/nexora/status", headers=vh).status_code == 403
    assert c.post("/api/v1/nexora/sync", headers=vh).status_code == 403


def test_the_stripe_webhook_is_ignored_when_linked(linked):
    cp, _, _, _ = linked
    assert cp.apply_stripe_webhook(b"{}", "t=1,v1=00") == "ignored"


@pytest.mark.parametrize("url", ["http://api.onenexora.com", "ftp://x", "api.onenexora.com"])
def test_nexora_urls_must_be_https(tmp_path, url):
    with pytest.raises(Exception, match="https"):
        load_settings(environment="test", data_dir=tmp_path, nexora={"api_url": url})


def test_empty_nexora_settings_mean_standalone(tmp_path):
    s = load_settings(
        environment="test",
        data_dir=tmp_path,
        nexora={"api_key": "", "api_url": "", "console_url": ""},
    )
    assert not s.nexora.linked and s.nexora.api_url == "https://api.onenexora.com"


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_a_non_finite_period_end_is_refused(tmp_path, bad):
    body = f'{{"org_id": "{ORG}", "plan_id": "pro", "current_period_end": {bad}}}'.encode()
    cp, client = make(tmp_path, lambda req: httpx.Response(200, content=body))
    with client:
        assert "unreadable" in cp.sync_nexora()["error"]
        assert cp.plan().plan_id.value == "community"
