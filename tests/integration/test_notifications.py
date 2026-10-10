import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.notify import derive_secret, sign
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import db
from neurawall.services.control_plane import service as service_module
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")
URL = "https://hooks.example.com/services/T000/B000/SECRETTOKEN"
PUBLIC = "93.184.216.34"


class Receiver:
    def __init__(self):
        self.status = 200
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        return httpx.Response(self.status)

    @property
    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


@pytest.fixture
def env(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN[1]},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    rx = Receiver()
    cp._notify_transport = httpx.MockTransport(rx)
    cp._resolver = lambda host, port: [PUBLIC]
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}, rx


def make_channel(c, h, **over):
    body = {"name": "soc", "url": URL, "events": ["alert.created", "draft.pending"], **over}
    r = c.post("/api/v1/notifications/channels", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def alert(cp, ref="7", severity="high"):
    cp._notify(
        "alert.created",
        ref,
        {"alert_id": int(ref), "severity": severity, "title": "C2 beacon", "labels": ["c2_beacon"]},
    )


def deliveries(cp):
    with cp.db.session() as s:
        return s.query(db.NotificationDelivery).order_by(db.NotificationDelivery.id).all()


def test_the_secret_is_shown_once_and_the_url_never(env):
    _, c, h, _ = env
    created = make_channel(c, h)
    assert created["signing_secret"].startswith("whsec_")
    assert created["url_hint"] == "https://hooks.example.com/…"
    listing = c.get("/api/v1/notifications/channels", headers=h)
    assert "SECRETTOKEN" not in listing.text and "signing_secret" not in listing.text
    audit = c.get("/api/v1/audit?limit=500", headers=h).text
    assert "SECRETTOKEN" not in audit and created["signing_secret"] not in audit


@pytest.mark.parametrize(
    "url",
    ["http://hooks.example.com/x", "https://127.0.0.1/x", "https://user:p@hooks.example.com/x"],
)
def test_unsafe_urls_cannot_be_saved(env, url):
    _, c, h, _ = env
    r = c.post(
        "/api/v1/notifications/channels",
        headers=h,
        json={"name": "bad", "url": url, "events": ["alert.created"]},
    )
    assert r.status_code == 422


def test_internal_names_cannot_be_saved(env):
    cp, c, h, _ = env
    cp._resolver = lambda host, port: ["169.254.169.254"]
    r = c.post(
        "/api/v1/notifications/channels",
        headers=h,
        json={"name": "meta", "url": URL, "events": ["alert.created"]},
    )
    assert r.status_code == 422 and "public" in r.text


def test_an_alert_is_delivered_signed_with_the_channel_secret(env):
    cp, c, h, rx = env
    secret = make_channel(c, h)["signing_secret"]
    alert(cp)
    assert cp.dispatch_notifications() == 1
    (req,) = rx.requests
    assert req.headers["host"] == "hooks.example.com" and req.url.host == PUBLIC
    assert req.url.path == "/services/T000/B000/SECRETTOKEN"
    ts = int(req.headers["x-neurawall-timestamp"])
    assert req.headers["x-neurawall-signature"] == sign(secret, ts, req.content)
    body = rx.bodies[0]
    assert body["event"] == "alert.created" and body["data"]["alert_id"] == 7
    assert "C2 beacon" in body["text"] and body["link"].endswith("/alerts/7")
    assert [d.status for d in deliveries(cp)] == ["sent"]


def test_each_event_is_delivered_once_per_channel(env):
    cp, c, h, rx = env
    make_channel(c, h)
    make_channel(c, h, name="pager")
    alert(cp)
    alert(cp)  # the same alert again
    assert cp.dispatch_notifications() == 2 and cp.dispatch_notifications() == 0
    assert len(rx.requests) == 2


def test_severity_and_event_filters(env):
    cp, c, h, _ = env
    make_channel(c, h, name="critical-only", min_severity="critical", events=["alert.created"])
    make_channel(c, h, name="drafts-only", events=["draft.pending"])
    alert(cp, "1", "high")
    alert(cp, "2", "critical")
    cp.dispatch_notifications()
    assert [d.ref for d in deliveries(cp)] == ["2"]
    cp.audit("alice", "draft.create", "draft:d-1")
    cp.dispatch_notifications()
    kinds = sorted((d.event_type, d.ref) for d in deliveries(cp))
    assert kinds == [("alert.created", "2"), ("draft.pending", "d-1")]


def test_a_paused_channel_receives_nothing(env):
    cp, c, h, rx = env
    ch = make_channel(c, h)
    assert (
        c.patch(
            f"/api/v1/notifications/channels/{ch['id']}", headers=h, json={"active": False}
        ).status_code
        == 200
    )
    alert(cp)
    cp.dispatch_notifications()
    assert rx.requests == [] and deliveries(cp) == []


def test_failures_are_retried_with_backoff_then_marked_dead(env, monkeypatch):
    cp, c, h, rx = env
    make_channel(c, h)
    rx.status = 500
    alert(cp)
    assert cp.dispatch_notifications() == 0
    (d,) = deliveries(cp)
    assert (d.status, d.attempts, d.http_status) == ("pending", 1, None)
    assert "500" in d.error and d.next_try_at > time.time()
    assert cp.dispatch_notifications() == 0 and len(rx.requests) == 1  # not due: no hammering
    real = service_module.time.time
    offset = 0
    for _ in range(cp.NOTIFY_MAX_ATTEMPTS - 1):
        offset += 4000
        monkeypatch.setattr(service_module.time, "time", lambda o=offset: real() + o)
        cp.dispatch_notifications()
    assert deliveries(cp)[0].status == "dead" and len(rx.requests) == cp.NOTIFY_MAX_ATTEMPTS


def test_a_receiver_that_recovers_gets_the_notification(env, monkeypatch):
    cp, c, h, rx = env
    make_channel(c, h)
    rx.status = 503
    alert(cp)
    cp.dispatch_notifications()
    rx.status = 200
    real = service_module.time.time
    monkeypatch.setattr(service_module.time, "time", lambda: real() + 3600)
    assert cp.dispatch_notifications() == 1
    assert deliveries(cp)[0].status == "sent"


def test_a_name_that_later_resolves_internally_is_never_contacted(env):
    cp, c, h, rx = env
    make_channel(c, h)
    cp._resolver = lambda host, port: ["10.0.0.9"]  # DNS changed after the channel was saved
    alert(cp)
    assert cp.dispatch_notifications() == 0
    assert rx.requests == []
    (d,) = deliveries(cp)
    assert d.status == "dead" and "public" in d.error  # permanent: no retries


def test_rotating_the_secret_invalidates_the_old_one(env):
    cp, c, h, rx = env
    ch = make_channel(c, h)
    rotated = c.patch(
        f"/api/v1/notifications/channels/{ch['id']}", headers=h, json={"rotate_secret": True}
    ).json()
    assert rotated["signing_secret"] != ch["signing_secret"]
    alert(cp)
    cp.dispatch_notifications()
    req = rx.requests[0]
    ts = int(req.headers["x-neurawall-timestamp"])
    sig = req.headers["x-neurawall-signature"]
    assert sig == sign(rotated["signing_secret"], ts, req.content)
    assert sig != sign(ch["signing_secret"], ts, req.content)


def test_the_secret_is_derived_not_stored(env):
    cp, c, h, _ = env
    ch = make_channel(c, h)
    with cp.db.session() as s:
        row = s.get(db.NotificationChannel, ch["id"])
        stored = json.dumps([row.name, row.url, row.secret_nonce, row.events])
    assert ch["signing_secret"] not in stored
    assert ch["signing_secret"] == derive_secret(cp.settings.jwt_secret, row.secret_nonce)


def test_test_message_reports_success_and_failure_and_is_rate_limited(env):
    _, c, h, rx = env
    ch = make_channel(c, h)
    ok = c.post(f"/api/v1/notifications/channels/{ch['id']}/test", headers=h).json()
    assert ok == {"ok": True, "status": 200, "error": None}
    assert "test message" in rx.bodies[0]["text"]
    rx.status = 500
    bad = c.post(f"/api/v1/notifications/channels/{ch['id']}/test", headers=h).json()
    assert bad["ok"] is False and "500" in bad["error"]
    codes = [
        c.post(f"/api/v1/notifications/channels/{ch['id']}/test", headers=h).status_code
        for _ in range(9)
    ]
    assert codes[-1] == 403  # 10 per hour


def test_deleting_a_channel_removes_its_deliveries(env):
    cp, c, h, _ = env
    ch = make_channel(c, h)
    alert(cp)
    cp.dispatch_notifications()
    assert len(deliveries(cp)) == 1
    assert c.delete(f"/api/v1/notifications/channels/{ch['id']}", headers=h).status_code == 204
    assert deliveries(cp) == []


def test_names_are_unique_and_only_admins_manage_channels(env):
    cp, c, h, _ = env
    make_channel(c, h)
    dup = c.post(
        "/api/v1/notifications/channels",
        headers=h,
        json={"name": "soc", "url": URL, "events": ["alert.created"]},
    )
    assert dup.status_code == 422
    c.post(
        "/api/v1/users",
        headers=h,
        json={
            "email": "o@example.com",
            "name": "O",
            "role": "operator",
            "password": "Operator-Pass-1!x",
        },
    )
    with cp.db.session() as s:
        s.query(db.User).filter_by(email="o@example.com").one().must_change_password = False
    t = c.post(
        "/api/v1/auth/login", json={"email": "o@example.com", "password": "Operator-Pass-1!x"}
    )
    oh = {"Authorization": f"Bearer {t.json()['access_token']}"}
    for call in (
        lambda: c.get("/api/v1/notifications/channels", headers=oh),
        lambda: c.get("/api/v1/notifications/deliveries", headers=oh),
        lambda: c.delete("/api/v1/notifications/channels/1", headers=oh),
    ):
        assert call().status_code == 403


def test_real_alerts_from_ingested_attacks_reach_the_channel(env):
    cp, c, h, rx = env
    make_channel(c, h, min_severity="low", events=["alert.created"])
    gen = TrafficGenerator(seed=3)
    flows = [gen.benign() for _ in range(80)] + list(gen.scenario("command_injection", 10))
    cp.ingest("edge-1", flows)
    assert cp.dispatch_notifications() >= 1
    assert all(b["event"] == "alert.created" for b in rx.bodies)


@pytest.mark.parametrize("name", ["   ", "\t", ""])
def test_a_blank_name_is_refused(env, name):
    _, c, h, _ = env
    r = c.post(
        "/api/v1/notifications/channels",
        headers=h,
        json={"name": name, "url": URL, "events": ["alert.created"]},
    )
    assert r.status_code == 422


def test_names_may_be_unicode_and_are_trimmed(env):
    _, c, h, _ = env
    r = c.post(
        "/api/v1/notifications/channels",
        headers=h,
        json={"name": "  Zespół SOC 🚨  ", "url": URL, "events": ["alert.created"]},
    )
    assert r.status_code == 201 and r.json()["name"] == "Zespół SOC 🚨"
