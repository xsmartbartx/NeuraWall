import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import db
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane

ADMIN = ("admin@neurawall.local", "Admin-Password-1!")


@pytest.fixture
def env(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        log_json=False,
        auth={"bootstrap_admin_password": ADMIN[1]},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}


def ingest_attacks(cp):
    gen = TrafficGenerator(seed=3)
    cp.ingest(
        "edge", [gen.benign() for _ in range(80)] + list(gen.scenario("command_injection", 12))
    )


def test_stats_count_matches_per_rule_and_leave_unmatched_rules_out(env):
    cp, c, h = env
    ingest_attacks(cp)
    body = c.get("/api/v1/rules/stats", headers=h).json()
    assert body["hours"] == 168
    rules = body["rules"]
    assert rules, "the starter rules match the injected attack flows"
    with cp.db.session() as s:
        expected = {}
        for (rid,) in s.query(db.FlowRow.rule_id).filter(db.FlowRow.rule_id.is_not(None)).all():
            expected[rid] = expected.get(rid, 0) + 1
    assert {k: v["matches"] for k, v in rules.items()} == expected
    all_rules = {r["id"] for r in c.get("/api/v1/rules", headers=h).json()}
    assert set(rules) <= all_rules and len(all_rules - set(rules)) > 0  # some never matched
    assert all(v["last_match"] > 0 for v in rules.values())


def test_stats_respect_the_window(env):
    cp, c, h = env
    ingest_attacks(cp)
    with cp.db.session() as s:
        for row in s.query(db.FlowRow).all():
            row.ts -= 3 * 86400  # three days old
    assert c.get("/api/v1/rules/stats?hours=24", headers=h).json()["rules"] == {}
    assert c.get("/api/v1/rules/stats?hours=96", headers=h).json()["rules"] != {}
    assert c.get("/api/v1/rules/stats?hours=0", headers=h).status_code == 422


def test_impact_replays_the_rule_against_recent_traffic(env):
    cp, c, h = env
    ingest_attacks(cp)
    rule_id = c.get("/api/v1/rules", headers=h).json()[0]["id"]
    r = c.get(f"/api/v1/rules/{rule_id}/impact", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["flows_evaluated"] > 0 and 0.0 <= body["blast_radius"] <= 1.0
    assert body["threshold"] == cp.settings.policy.blast_radius_threshold
    assert c.get("/api/v1/rules/R-999999/impact", headers=h).status_code == 404


def test_both_need_a_signed_in_reader(env):
    _, c, _ = env
    assert c.get("/api/v1/rules/stats").status_code == 401
    assert c.get("/api/v1/rules/R-000001/impact").status_code == 401


def make_redundant_rule(c, h):
    first = next(r for r in c.get("/api/v1/rules", headers=h).json() if r["id"] == "R-000002")
    draft = c.post(
        "/api/v1/drafts",
        headers=h,
        json={
            "name": "Duplicate",
            "rationale": "covered by an earlier rule",
            "action": first["action"],
            "priority": 900,
            "match": first["match"],
        },
    ).json()
    draft_id = draft.get("draft", draft).get("draft_id") or draft["id"]
    ok = c.post(
        f"/api/v1/drafts/{draft_id}/approve",
        headers=h,
        json={"mode": "alert_only", "note": "t", "acknowledge_blast_radius": True},
    )
    assert ok.status_code == 200, ok.text
    return next(
        f["rule_id"]
        for f in c.get("/api/v1/rules/hygiene", headers=h).json()
        if f["kind"] == "redundant"
    )


def test_disabling_a_redundant_rule_clears_the_finding_and_changes_no_verdict(env):
    cp, c, h = env
    rule_id = make_redundant_rule(c, h)
    ingest_attacks(cp)
    stats = c.get("/api/v1/rules/stats", headers=h).json()["rules"]
    assert rule_id not in stats  # it can never match: the covering rule takes the traffic first
    verdicts_before = c.get("/api/v1/flows?limit=500", headers=h).json()["total"]
    r = c.patch(f"/api/v1/rules/{rule_id}", headers=h, json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert [
        f for f in c.get("/api/v1/rules/hygiene", headers=h).json() if f["rule_id"] == rule_id
    ] == []
    ingest_attacks(cp)
    assert c.get("/api/v1/flows?limit=500", headers=h).json()["total"] >= verdicts_before
    actions = [a["action"] for a in c.get("/api/v1/audit?limit=20", headers=h).json()["items"]]
    assert "rule.update" in actions and cp.verify_audit() > 0
