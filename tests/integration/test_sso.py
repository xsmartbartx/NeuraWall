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


def test_audience_is_enforced_when_configured(tmp_path):
    with build_client(
        tmp_path, sso_jwks_url=JWKS, sso_issuer=ISSUER, sso_audience="neurawall"
    ) as c:
        assert sso_login(c, make_token(email=ADMIN[0])).status_code == 403
        assert sso_login(c, make_token(email=ADMIN[0], aud="something-else")).status_code == 403
        assert sso_login(c, make_token(email=ADMIN[0], aud="neurawall")).status_code == 200


def test_sso_config_is_off_by_default_and_public(tmp_path):
    with build_client(tmp_path) as c:
        r = c.get("/api/v1/auth/sso/config")
        assert r.status_code == 200
        assert r.json() == {
            "enabled": False,
            "login_url": None,
            "jit": False,
            "local_login": "enabled",
            "demo": False,
        }


def test_sso_config_needs_both_the_verifier_and_a_login_url(tmp_path):
    only_verifier = build_client(tmp_path / "a", sso_jwks_url=JWKS)
    only_url = build_client(tmp_path / "b", sso_login_url="https://account.test/sso/neurawall")
    both = build_client(
        tmp_path / "c", sso_jwks_url=JWKS, sso_login_url="https://account.test/sso/neurawall"
    )
    with only_verifier as c:
        assert c.get("/api/v1/auth/sso/config").json()["enabled"] is False
    with only_url as c:
        assert c.get("/api/v1/auth/sso/config").json()["enabled"] is False
    with both as c:
        assert c.get("/api/v1/auth/sso/config").json() == {
            "enabled": True,
            "login_url": "https://account.test/sso/neurawall",
            "jit": False,
            "local_login": "enabled",
            "demo": False,
        }


def test_empty_settings_mean_not_configured(tmp_path):
    """Compose passes unset variables through as empty strings."""
    with build_client(
        tmp_path,
        sso_jwks_url=JWKS,
        sso_issuer="",
        sso_audience="",
        sso_required_org_id="",
        sso_login_url="",
    ) as c:
        assert sso_login(c, make_token(email=ADMIN[0])).status_code == 200
        assert c.get("/api/v1/auth/sso/config").json()["enabled"] is False


# ---------------------------------------------------------------- just-in-time users

ORG = "org_ok"


def jit_client(tmp_path, **extra):
    return build_client(
        tmp_path,
        sso_jwks_url=JWKS,
        sso_issuer=ISSUER,
        sso_required_org_id=ORG,
        sso_jit=True,
        **extra,
    )


def member(**claims):
    base = {"sub": "user_new", "email": "new@example.com", "org_id": ORG, "email_verified": True}
    return make_token(**{**base, **claims})


def admin_headers(c):
    r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_jit_needs_an_organisation(tmp_path):
    with pytest.raises(Exception, match="sso_jit"):
        load_settings(
            environment="test",
            data_dir=tmp_path,
            auth={"sso_jwks_url": JWKS, "sso_jit": True},
        )


def test_jit_creates_a_viewer_and_audits_it(tmp_path):
    with jit_client(tmp_path) as c:
        r = sso_login(c, member())
        assert r.status_code == 200, r.text
        user = r.json()["user"]
        assert (user["email"], user["role"], user["auth_provider"]) == (
            "new@example.com",
            "viewer",
            "nexora",
        )
        assert r.json()["expires_in"] == 3600
        actions = [
            e["action"] for e in c.get("/api/v1/audit", headers=admin_headers(c)).json()["items"]
        ]
        assert "auth.sso.provision" in actions


def test_jit_never_takes_a_role_from_the_token(tmp_path):
    with jit_client(tmp_path) as c:
        r = sso_login(c, member(role="admin", org_role="org:admin", o={"id": ORG, "rol": "admin"}))
        assert r.json()["user"]["role"] == "viewer"


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({"email_verified": False}, id="unverified"),
        pytest.param({"email_verified": "true"}, id="verified-as-a-string"),
        pytest.param({"org_id": "org_other"}, id="other-organisation"),
        pytest.param({"org_id": None}, id="no-organisation"),
    ],
)
def test_jit_refuses_unverified_or_outside_identities(tmp_path, claims):
    with jit_client(tmp_path) as c:
        assert sso_login(c, member(**claims)).status_code == 403
        users = c.get("/api/v1/users", headers=admin_headers(c)).json()
        assert [u["email"] for u in users] == [ADMIN[0]]  # the refusal created nobody


def test_jit_needs_the_verified_claim_to_be_present(tmp_path):
    with jit_client(tmp_path) as c:
        token = make_token(sub="user_new", email="new@example.com", org_id=ORG)
        assert sso_login(c, token).status_code == 403


def test_a_returning_user_is_matched_by_provider_id_not_email(tmp_path):
    with jit_client(tmp_path) as c:
        first = sso_login(c, member()).json()["user"]
        again = sso_login(c, member(email="renamed@example.com")).json()["user"]
        assert again["id"] == first["id"]
        assert again["email"] == "new@example.com"


def test_an_existing_email_is_linked_once(tmp_path):
    with jit_client(tmp_path) as c:
        assert sso_login(c, member(sub="user_a", email=ADMIN[0])).json()["user"]["role"] == "admin"
        # Same email, different provider identity: refused, not re-linked.
        assert sso_login(c, member(sub="user_b", email=ADMIN[0])).status_code == 403


def test_a_deactivated_jit_user_stays_out(tmp_path):
    with jit_client(tmp_path) as c:
        uid = sso_login(c, member()).json()["user"]["id"]
        patched = c.patch(f"/api/v1/users/{uid}", headers=admin_headers(c), json={"active": False})
        assert patched.status_code == 200
        assert sso_login(c, member()).status_code == 403


def test_a_jit_user_has_no_usable_password(tmp_path):
    with jit_client(tmp_path) as c:
        uid = sso_login(c, member()).json()["user"]["id"]
        login = c.post("/api/v1/auth/login", json={"email": "new@example.com", "password": "x"})
        assert login.status_code == 403
        reset = c.post(f"/api/v1/users/{uid}/reset-password", headers=admin_headers(c))
        assert reset.status_code == 422


def test_sso_session_lifetime_is_configurable(tmp_path):
    with jit_client(tmp_path, sso_session_ttl_seconds=900) as c:
        assert sso_login(c, member()).json()["expires_in"] == 900
    with build_client(tmp_path / "plain", sso_jwks_url=JWKS) as c:
        assert sso_login(c, make_token(email=ADMIN[0])).json()["expires_in"] == 8 * 3600


def test_admin_only_keeps_password_sign_in_for_admins(tmp_path):
    with build_client(tmp_path, sso_jwks_url=JWKS, local_login="admin_only") as c:
        assert c.get("/api/v1/auth/sso/config").json()["local_login"] == "admin_only"
        headers = admin_headers(c)  # an admin can still sign in with the password
        created = c.post(
            "/api/v1/users",
            headers=headers,
            json={
                "email": "viewer@example.com",
                "name": "Viewer",
                "role": "viewer",
                "password": "Viewer-Password-1!",
            },
        )
        assert created.status_code == 201
        refused = c.post(
            "/api/v1/auth/login",
            json={"email": "viewer@example.com", "password": "Viewer-Password-1!"},
        )
        wrong = c.post(
            "/api/v1/auth/login", json={"email": "viewer@example.com", "password": "nope"}
        )
        assert refused.status_code == wrong.status_code == 403
        assert refused.json() == wrong.json()  # indistinguishable


def test_an_overlong_subject_is_refused_not_truncated(tmp_path):
    """Two long ids that share a prefix must never collapse into one account."""
    with jit_client(tmp_path) as c:
        a = sso_login(c, member(sub="u" * 64 + "a", email="a@example.com"))
        b = sso_login(c, member(sub="u" * 64 + "b", email="b@example.com"))
        assert a.status_code == b.status_code == 403


def test_a_concurrent_first_sign_in_is_a_clean_refusal_not_a_500(tmp_path, monkeypatch):
    """Two tabs finishing the first SSO sign-in at once: the unique constraint stops the second
    insert. That must be an ordinary refusal (the retry succeeds), never a server error."""
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    with jit_client(tmp_path) as c:
        real_flush = Session.flush
        state = {"armed": True}

        def colliding_flush(self, *args, **kwargs):
            if state["armed"] and any(type(o).__name__ == "User" for o in self.new):
                state["armed"] = False
                raise IntegrityError("INSERT INTO users", {}, Exception("UNIQUE external_id"))
            return real_flush(self, *args, **kwargs)

        monkeypatch.setattr(Session, "flush", colliding_flush)
        assert sso_login(c, member()).status_code == 403
        assert sso_login(c, member()).status_code == 200  # the retry works


def test_an_overlong_email_is_refused_not_a_server_error(tmp_path):
    with jit_client(tmp_path) as c:
        assert sso_login(c, member(email="a" * 250 + "@example.com")).status_code == 403


def test_last_login_is_saved_for_password_and_sso_sign_in(client):
    """Regression: the user used to be detached before the update was flushed."""
    login = client.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
    first = client.get("/api/v1/users", headers=admin).json()[0]["last_login"]
    assert first is not None
    time.sleep(0.01)
    assert sso_login(client, make_token(email=ADMIN[0])).status_code == 200
    assert client.get("/api/v1/users", headers=admin).json()[0]["last_login"] > first


def _external_id(c, email):
    from neurawall.services.control_plane import db

    with c.app.state.cp.db.session() as s:
        return s.query(db.User).filter_by(email=email).one().external_id


def test_an_unverified_token_cannot_claim_an_existing_account_in_strict_mode(tmp_path):
    with jit_client(tmp_path) as c:
        assert (
            sso_login(c, member(sub="user_x", email=ADMIN[0], email_verified=False)).status_code
            == 403
        )
        assert _external_id(c, ADMIN[0]) is None  # nothing was bound
        # The real owner, with a verified email, is not locked out.
        assert sso_login(c, member(sub="user_owner", email=ADMIN[0])).status_code == 200
        assert _external_id(c, ADMIN[0]) == "user_owner"


def test_without_jit_an_unverified_token_signs_in_but_never_binds(client):
    """Existing behaviour is kept (the identity provider must verify emails), but only a
    verified email may bind the provider id to the account."""
    assert sso_login(client, make_token(sub="user_x", email=ADMIN[0])).status_code == 200
    assert _external_id(client, ADMIN[0]) is None
    assert (
        sso_login(
            client, make_token(sub="user_ok", email=ADMIN[0], email_verified=True)
        ).status_code
        == 200
    )
    assert _external_id(client, ADMIN[0]) == "user_ok"
