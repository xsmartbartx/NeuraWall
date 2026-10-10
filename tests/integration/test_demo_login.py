import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")


def client(tmp_path, **over):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={
            "bootstrap_admin_password": ADMIN[1],
            "demo_public_login": True,
            "login_rate_per_minute": 50,
        },
        **over,
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    return TestClient(create_app(settings, control_plane=cp, start_background=False))


def test_off_by_default(tmp_path):
    settings = load_settings(
        environment="test", data_dir=tmp_path, auth={"bootstrap_admin_password": ADMIN[1]}
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        assert c.post("/api/v1/auth/demo").status_code == 404
        assert c.get("/api/v1/auth/sso/config").json()["demo"] is False


def test_a_guest_is_a_read_only_viewer_with_a_short_session(tmp_path):
    with client(tmp_path, demo_mode=True) as c:
        assert c.get("/api/v1/auth/sso/config").json()["demo"] is True
        r = c.post("/api/v1/auth/demo")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user"]["role"] == "viewer" and body["expires_in"] == 1800
        h = {"Authorization": f"Bearer {body['access_token']}"}
        assert c.get("/api/v1/alerts", headers=h).status_code == 200
        for method, path in (
            ("delete", "/api/v1/rules/R-0001"),
            ("get", "/api/v1/users"),
            ("get", "/api/v1/audit"),
            ("get", "/api/v1/nexora/status"),
            ("get", "/api/v1/audit/export.csv"),
            ("get", "/api/v1/notifications/channels"),
            ("post", "/api/v1/nodes/enrollment-tokens"),
        ):
            assert getattr(c, method)(path, headers=h).status_code == 403, path
        # The same account every time, and it cannot sign in with a password.
        again = c.post("/api/v1/auth/demo").json()
        assert again["user"]["id"] == body["user"]["id"]
        login = c.post(
            "/api/v1/auth/login", json={"email": "demo@neurawall.local", "password": "x"}
        )
        assert login.status_code == 403


def test_the_guest_account_is_refused_if_an_admin_changes_it(tmp_path):
    with client(tmp_path, demo_mode=True) as c:
        uid = c.post("/api/v1/auth/demo").json()["user"]["id"]
        t = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        h = {"Authorization": f"Bearer {t.json()['access_token']}"}
        assert c.patch(f"/api/v1/users/{uid}", headers=h, json={"role": "admin"}).status_code == 200
        assert c.post("/api/v1/auth/demo").status_code == 404


def test_it_is_rate_limited_per_address(tmp_path):
    with client(tmp_path, demo_mode=True) as c:
        codes = [c.post("/api/v1/auth/demo").status_code for _ in range(7)]
        assert codes[:5] == [200] * 5 and set(codes[5:]) == {403}


@pytest.mark.parametrize(
    "over,message",
    [
        ({}, "demo_mode"),
        ({"demo_mode": True, "nexora": {"api_key": "nx_live_x"}}, "linked"),
        ({"demo_mode": True, "billing": {"stripe_secret_key": "sk_test_x"}}, "billing keys"),
        ({"demo_mode": True, "llm": {"api_key": "sk-ant-x"}}, "offline advisor"),
    ],
)
def test_it_cannot_be_enabled_on_a_real_installation(tmp_path, over, message):
    with pytest.raises(Exception, match=message):
        load_settings(
            environment="test", data_dir=tmp_path, auth={"demo_public_login": True}, **over
        )
