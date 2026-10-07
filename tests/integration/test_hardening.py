"""Responses must not echo internals, and odd static paths must not 500 (CodeQL findings)."""

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.core.errors import IntegrityFailure
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import app as app_module
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")


def _settings(tmp_path):
    return load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        inference={"baseline_warmup_flows": 50, "isolation_forest_trees": 20},
        auth={"bootstrap_admin_password": ADMIN[1], "login_rate_per_minute": 30},
    )


def _login(c):
    r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def static_client(tmp_path, monkeypatch):
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<html>console</html>")
    (static / "app.txt").write_text("asset")
    (tmp_path / "secret.txt").write_text("TOP SECRET")
    monkeypatch.setattr(app_module, "STATIC_DIR", static)
    settings = _settings(tmp_path / "data")
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        yield c


def test_static_serving_survives_odd_paths(static_client):
    assert static_client.get("/app.txt").text == "asset"
    # An embedded NUL byte is a 404, not a 500.
    assert static_client.get("/app%00.txt").status_code == 404
    # Traversal falls back to the SPA shell and never serves the file outside the folder.
    for path in ("/..%2fsecret.txt", "/%2e%2e/secret.txt", "/..%2f..%2fetc/passwd"):
        r = static_client.get(path)
        assert "TOP SECRET" not in r.text and "root:" not in r.text


def test_audit_verify_does_not_echo_internals(tmp_path):
    settings = _settings(tmp_path)
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        h = _login(c)

        def broken():
            raise IntegrityFailure("audit chain broken at seq 3: prev_hash mismatch")

        cp.verify_audit = broken
        body = c.get("/api/v1/audit/verify", headers=h).json()
        assert body["valid"] is False and "seq 3" not in body["error"]

        def crashed():
            raise RuntimeError("db password=hunter2 host=10.0.0.5")

        cp.verify_audit = crashed
        body = c.get("/api/v1/audit/verify", headers=h).json()
        assert body["valid"] is False
        assert "hunter2" not in body["error"] and "10.0.0.5" not in body["error"]


def test_flow_ingest_errors_do_not_echo_validation_text(tmp_path):
    settings = _settings(tmp_path)
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        h = _login(c)
        token = c.post("/api/v1/nodes/enrollment-tokens", headers=h, json={}).json()["token"]
        enr = c.post("/api/v1/agent/enroll", json={"token": token, "name": "edge-1"}).json()
        nh = {"Authorization": f"Bearer {enr['api_key']}"}
        bad = [
            {"src_ip": "not-an-ip", "dst_ip": "1.1.1.1"},
            {"src_ip": "10.0.0.1", "dst_port": "x"},
        ]
        out = c.post("/api/v1/agent/flows", headers=nh, json={"flows": bad}).json()
        assert out["rejected"] == 2
        assert out["errors"] == [
            "record 0: not a valid flow record",
            "record 1: not a valid flow record",
        ]
