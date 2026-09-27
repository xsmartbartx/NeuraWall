import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")


@pytest.fixture
def client(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        inference={"baseline_warmup_flows": 50, "isolation_forest_trees": 20},
        auth={"bootstrap_admin_password": ADMIN[1], "login_rate_per_minute": 30},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    app = create_app(settings, control_plane=cp, start_background=False)
    with TestClient(app) as c:
        yield c


def login(c, email=ADMIN[0], password=ADMIN[1]):
    r = c.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_health_and_security_headers(client):
    r = client.get("/healthz")
    assert r.json() == {"status": "ok"}
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert client.get("/metrics").status_code == 200


def test_auth_required_and_login(client):
    assert client.get("/api/v1/rules").status_code == 401
    assert client.get("/api/v1/rules", headers={"Authorization": "Bearer junk"}).status_code == 401
    bad = client.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": "nope"})
    assert bad.status_code == 403
    h = login(client)
    me = client.get("/api/v1/auth/me", headers=h).json()
    assert me["role"] == "admin" and "rules:approve" in me["permissions"]
    assert len(client.get("/api/v1/rules", headers=h).json()) == 7


def test_rbac_viewer_cannot_approve_and_must_change_password(client):
    h = login(client)
    r = client.post(
        "/api/v1/users",
        headers=h,
        json={
            "email": "viewer@corp.io",
            "name": "V",
            "role": "viewer",
            "password": "Viewer-Pass-12",
        },
    )
    assert r.status_code == 201
    vh = login(client, "viewer@corp.io", "Viewer-Pass-12")
    assert client.get("/api/v1/rules", headers=vh).status_code == 403  # must change password
    assert (
        client.post(
            "/api/v1/auth/password",
            headers=vh,
            json={"current_password": "Viewer-Pass-12", "new_password": "Viewer-Pass-34!"},
        ).status_code
        == 200
    )
    assert client.get("/api/v1/rules", headers=vh).status_code == 200
    assert (
        client.patch("/api/v1/rules/R-000001", headers=vh, json={"enabled": False}).status_code
        == 403
    )
    assert client.get("/api/v1/users", headers=vh).status_code == 403


def test_validation_rejects_unknown_fields(client):
    h = login(client)
    r = client.post(
        "/api/v1/drafts",
        headers=h,
        json={
            "name": "x",
            "rationale": "y",
            "action": "drop",
            "match": {"dst_ports": [1]},
            "evil": 1,
        },
    )
    assert r.status_code == 422
    r = client.post(
        "/api/v1/drafts",
        headers=h,
        json={"name": "x", "rationale": "y", "action": "drop", "match": {}},
    )
    assert r.status_code == 422


def test_agent_enroll_ingest_and_block_roundtrip(client):
    h = login(client)
    token = client.post("/api/v1/nodes/enrollment-tokens", headers=h, json={}).json()["token"]
    enr = client.post("/api/v1/agent/enroll", json={"token": token, "name": "edge-1"}).json()
    nh = {"Authorization": f"Bearer {enr['api_key']}"}
    # A node key cannot be used as a user session and vice versa.
    assert client.get("/api/v1/rules", headers=nh).status_code == 401
    assert client.get("/api/v1/agent/bundle", headers=h).status_code == 401

    bundle = client.get("/api/v1/agent/bundle", headers=nh).json()
    assert bundle["key_id"] == enr["signing_key_id"] and bundle["payload"]["version"] == 1

    gen = TrafficGenerator(seed=3)
    benign = [f.model_dump(mode="json") for f in (gen.benign() for _ in range(200))]
    assert (
        client.post("/api/v1/agent/flows", headers=nh, json={"flows": benign}).json()["accepted"]
        == 200
    )
    attack = [f.model_dump(mode="json") for f in gen.scenario("command_injection", 10)]
    attack.append({"src_ip": "not-an-ip", "dst_ip": "1.1.1.1"})
    out = client.post("/api/v1/agent/flows", headers=nh, json={"flows": attack}).json()
    assert out["rejected"] == 1 and out["verdicts"]
    assert all(v["verdict"]["rule_id"] for v in out["verdicts"])

    hb = client.post(
        "/api/v1/agent/heartbeat",
        headers=nh,
        json={"applied_version": 1, "backend": "dry-run", "stats": {"active_blocks": 3}},
    )
    assert hb.status_code == 200
    nodes = client.get("/api/v1/nodes", headers=h).json()
    assert nodes[0]["status"] == "online" and nodes[0]["up_to_date"]

    alerts = client.get("/api/v1/alerts", headers=h).json()
    assert alerts["total"] >= 1
    aid = alerts["items"][0]["id"]
    triaged = client.post(f"/api/v1/alerts/{aid}/triage", headers=h).json()
    assert triaged["id"] == aid and triaged["summary"] and not triaged["tier3_pending"]
    # Fully blocked by an existing rule: no redundant draft is proposed.
    assert (triaged["draft_id"] is None) == (triaged["blocked_count"] == triaged["flow_count"])
    flows = client.get(f"/api/v1/flows?alert_id={aid}", headers=h).json()
    assert flows["total"] >= 1
    fid = flows["items"][0]["flow_id"]
    assert client.get(f"/api/v1/flows/{fid}", headers=h).json()["verdict"]["action"]
    assert client.post(f"/api/v1/flows/{fid}/explain", headers=h).json()["explanation"]


def test_draft_approve_flow_via_api(client):
    h = login(client)
    d = client.post(
        "/api/v1/drafts",
        headers=h,
        json={
            "name": "Block 4444",
            "rationale": "Metasploit default port",
            "action": "drop",
            "match": {"dst_ports": [4444], "protocols": ["tcp"]},
        },
    ).json()
    assert d["draft"]["simulation"] is not None
    r = client.post(f"/api/v1/drafts/{d['id']}/approve", headers=h, json={"mode": "enforce"})
    assert r.status_code == 200 and r.json()["id"] == "R-000008"
    bundles = client.get("/api/v1/bundles", headers=h).json()
    assert bundles[0]["version"] == 2 and bundles[0]["rollout_percent"] == 5
    assert client.post("/api/v1/bundles/2/advance", headers=h).json()["rollout_percent"] == 25
    audit = client.get("/api/v1/audit/verify", headers=h).json()
    assert audit["valid"] and audit["entries"] > 3


def test_dashboard(client):
    h = login(client)
    d = client.get("/api/v1/dashboard", headers=h).json()
    assert d["active_rules"] == 7 and d["advisor_mode"] == "offline"


def test_login_rate_limit(client):
    codes = [
        client.post("/api/v1/auth/login", json={"email": "x@y.z", "password": "p"}).status_code
        for _ in range(40)
    ]
    assert (
        codes.count(403) >= 30
        and "too many"
        in client.post("/api/v1/auth/login", json={"email": "x@y.z", "password": "p"}).json()[
            "message"
        ]
    )
