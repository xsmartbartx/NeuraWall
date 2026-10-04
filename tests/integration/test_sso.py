"""Opt-in Clerk single sign-on: a verified identity signs in as an *existing*
NeuraWall user; roles, deactivation and four-eyes stay NeuraWall's.
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.security import sso
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")
JWKS = "https://clerk.test/.well-known/jwks.json"
ISSUER = "https://clerk.test"
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _FakeJwks:
    def get_signing_key_from_jwt(self, token):
        class _K:
            key = _KEY.public_key()

        return _K()


def make_token(**claims):
    now = int(time.time())
    payload = {"sub": "user_1", "iat": now, "exp": now + 600, "iss": ISSUER, **claims}
    return jwt.encode(payload, _KEY, algorithm="RS256")


def build_client(tmp_path, **auth):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        inference={"baseline_warmup_flows": 50, "isolation_forest_trees": 20},
        auth={"bootstrap_admin_password": ADMIN[1], "login_rate_per_minute": 30, **auth},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    return TestClient(create_app(settings, control_plane=cp, start_background=False))


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch):
    monkeypatch.setattr(sso, "_jwk_client", lambda url: _FakeJwks())


@pytest.fixture
def client(tmp_path):
    with build_client(tmp_path, sso_jwks_url=JWKS, sso_issuer=ISSUER) as c:
        yield c


def sso_login(c, token):
    return c.post("/api/v1/auth/sso", json={"token": token})


def test_disabled_by_default(tmp_path):
    with build_client(tmp_path) as c:
        assert sso_login(c, make_token(email=ADMIN[0])).status_code == 404


def test_signs_in_an_existing_user_with_their_own_role(client):
    r = sso_login(client, make_token(email=ADMIN[0].upper()))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["email"] == ADMIN[0]
    assert body["user"]["role"] == "admin"
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200


def test_never_creates_a_user_for_an_unknown_identity(client):
    assert sso_login(client, make_token(email="stranger@example.com")).status_code == 403


def test_a_deactivated_user_cannot_use_sso(client):
    login = client.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
    created = client.post(
        "/api/v1/users",
        headers=admin,
        json={
            "email": "viewer@example.com",
            "name": "Viewer",
            "role": "viewer",
            "password": "Viewer-Password-1!",
        },
    )
    assert created.status_code == 201, created.text
    uid = created.json()["id"]
    assert sso_login(client, make_token(email="viewer@example.com")).status_code == 200
    client.patch(f"/api/v1/users/{uid}", headers=admin, json={"active": False})
    assert sso_login(client, make_token(email="viewer@example.com")).status_code == 403


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(make_token(email=ADMIN[0], exp=int(time.time()) - 60), id="expired"),
        pytest.param(make_token(email=ADMIN[0], iss="https://evil.test"), id="wrong-issuer"),
        pytest.param(make_token(), id="no-email"),
        pytest.param("not-a-jwt-but-long-enough-to-pass-validation", id="garbage"),
    ],
)
def test_rejects_bad_tokens(client, token):
    assert sso_login(client, token).status_code == 403


def test_a_token_signed_by_another_key_is_rejected(client):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = jwt.encode(
        {"sub": "u", "exp": now + 600, "iss": ISSUER, "email": ADMIN[0]}, other, algorithm="RS256"
    )
    assert sso_login(client, forged).status_code == 403


def test_organisation_can_be_required(tmp_path):
    with build_client(
        tmp_path, sso_jwks_url=JWKS, sso_issuer=ISSUER, sso_required_org_id="org_ok"
    ) as c:
        assert sso_login(c, make_token(email=ADMIN[0])).status_code == 403
        assert sso_login(c, make_token(email=ADMIN[0], org_id="org_other")).status_code == 403
        assert sso_login(c, make_token(email=ADMIN[0], org_id="org_ok")).status_code == 200
        assert sso_login(c, make_token(email=ADMIN[0], o={"id": "org_ok"})).status_code == 200


def test_the_password_login_is_unchanged(client):
    r = client.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert r.status_code == 200
