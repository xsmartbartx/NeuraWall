"""The audit chain never holds an email (so a person can be erased), and erasing removes what
identifies them everywhere else without breaking the chain."""

import json

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.core.errors import PolicyViolation
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import db
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")
PASSWORD = "Operator-Pass-1!xyz"


@pytest.fixture
def env(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN[1], "login_rate_per_minute": 100},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}


def make_user(cp, c, h, email, role="operator"):
    r = c.post(
        "/api/v1/users",
        headers=h,
        json={"email": email, "name": "Op", "role": role, "password": PASSWORD},
    )
    assert r.status_code == 201, r.text
    with cp.db.session() as s:
        s.query(db.User).filter_by(email=email).one().must_change_password = False
    return r.json()["id"]


def login(c, email):
    r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    return r, {"Authorization": f"Bearer {r.json().get('access_token', '')}"}


def audit_text(cp):
    with cp.db.session() as s:
        return json.dumps(
            [(r.actor, r.action, r.target, r.detail) for r in s.query(db.AuditRow).all()]
        )


def test_no_email_is_written_to_the_audit_chain(env):
    cp, c, h = env
    uid = make_user(cp, c, h, "ops@example.com")
    _, oh = login(c, "ops@example.com")  # signs in: audited
    c.post("/api/v1/nodes/enrollment-tokens", headers=oh, json={})  # may be refused: still no email
    c.post(f"/api/v1/users/{uid}/reset-password", headers=h)
    text = audit_text(cp)
    assert "@" not in text, text
    with cp.db.session() as s:
        actors = {r.actor for r in s.query(db.AuditRow).all()}
    assert f"user:{uid}" in actors
    assert "user:1" in actors  # people are named by id
    assert cp.verify_audit() > 0


def test_user_create_records_the_role_not_the_email(env):
    cp, c, h = env
    make_user(cp, c, h, "ops@example.com", role="analyst")
    with cp.db.session() as s:
        row = s.query(db.AuditRow).filter_by(action="user.create").one()
    assert row.detail == {"role": "analyst"}


def test_an_alert_assignee_is_recorded_by_id(env):
    cp, c, h = env
    make_user(cp, c, h, "ops@example.com")
    gen_flows = __import__("neurawall.modules.flow_collector.generator", fromlist=["x"])
    gen = gen_flows.TrafficGenerator(seed=3)
    cp.ingest(
        "edge", [gen.benign() for _ in range(60)] + list(gen.scenario("command_injection", 10))
    )
    alert_id = c.get("/api/v1/alerts", headers=h).json()["items"][0]["id"]
    r = c.patch(f"/api/v1/alerts/{alert_id}", headers=h, json={"assignee": "ops@example.com"})
    assert r.status_code == 200
    assert "ops@example.com" not in audit_text(cp)


def test_erasing_removes_the_person_everywhere_and_the_chain_still_verifies(env):
    cp, c, h = env
    uid = make_user(cp, c, h, "ops@example.com")
    _, oh = login(c, "ops@example.com")
    cp.create_enrollment_token("ops@example.com")  # a table that records the email
    before = cp.verify_audit()
    assert c.delete(f"/api/v1/users/{uid}", headers=h).status_code == 204
    with cp.db.session() as s:
        u = s.get(db.User, uid)
        assert (u.email, u.name, u.active) == (f"erased-{uid}@erased.invalid", "Erased user", False)
        assert u.external_id is None
        assert u.auth_provider == "local"
        tokens = [t.created_by for t in s.query(db.EnrollmentToken).all()]
    assert "ops@example.com" not in tokens
    assert f"erased-{uid}@erased.invalid" in tokens
    assert cp.verify_audit() >= before  # the chain is intact (and has the erase entry)
    erased = [
        r
        for r in c.get("/api/v1/audit?limit=50", headers=h).json()["items"]
        if r["action"] == "user.erase"
    ]
    assert erased
    assert "@" not in json.dumps(erased)
    # They are out: the old email and password no longer work, and an existing session is dead.
    assert (
        c.post(
            "/api/v1/auth/login", json={"email": "ops@example.com", "password": PASSWORD}
        ).status_code
        == 403
    )
    assert c.get("/api/v1/auth/me", headers=oh).status_code == 401


def test_the_audit_export_holds_no_email_after_an_erase(env):
    cp, c, h = env
    uid = make_user(cp, c, h, "ops@example.com")
    login(c, "ops@example.com")
    c.delete(f"/api/v1/users/{uid}", headers=h)
    csv_text = c.get("/api/v1/audit/export.csv", headers=h).text
    assert "ops@example.com" not in csv_text


def test_erase_is_refused_for_yourself_and_twice_and_for_unknown_ids(env):
    cp, c, h = env
    me = c.get("/api/v1/auth/me", headers=h).json()["id"]
    assert c.delete(f"/api/v1/users/{me}", headers=h).status_code == 403  # yourself
    uid = make_user(cp, c, h, "ops@example.com")
    assert c.delete(f"/api/v1/users/{uid}", headers=h).status_code == 204
    assert c.delete(f"/api/v1/users/{uid}", headers=h).status_code == 422  # already erased
    assert c.delete("/api/v1/users/9999", headers=h).status_code == 404


def test_the_last_active_administrator_cannot_be_erased(env):
    cp, c, h = env
    second = make_user(cp, c, h, "second@example.com", role="admin")
    cp.erase_user("someone@example.com", second)  # two admins: one may go
    with pytest.raises(PolicyViolation, match="last active administrator"):
        cp.erase_user("someone@example.com", c.get("/api/v1/auth/me", headers=h).json()["id"])


def test_only_user_admins_can_erase(env):
    cp, c, h = env
    victim = make_user(cp, c, h, "victim@example.com")
    make_user(cp, c, h, "ops@example.com")
    _, oh = login(c, "ops@example.com")
    assert c.delete(f"/api/v1/users/{victim}", headers=oh).status_code == 403
    assert c.delete(f"/api/v1/users/{victim}").status_code == 401
