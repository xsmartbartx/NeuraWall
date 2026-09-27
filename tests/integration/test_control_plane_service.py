import pytest

from neurawall.core.config import load_settings
from neurawall.core.errors import IntegrityFailure, PolicyViolation
from neurawall.core.models import Action, RuleMatch, RuleMode, SignedEnvelope, ThreatLabel
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.policy_engine import open_bundle
from neurawall.security.integrity import EphemeralSigner, load_public_key
from neurawall.security.rbac import Role
from neurawall.services.control_plane import db
from neurawall.services.control_plane.service import ControlPlane


@pytest.fixture
def cp(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        inference={"baseline_warmup_flows": 50, "isolation_forest_trees": 20},
        auth={"bootstrap_admin_password": "Admin-Password-1!"},
        policy={"rollout_stage_seconds": 0},
        billing={"plan": "enterprise"},
    )
    plane = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    yield plane
    plane.stop()


def warm(cp, gen, n=300):
    cp.ingest("n1", [gen.benign() for _ in range(n)])


def test_bootstrap_admin_starter_rules_and_initial_bundle(cp):
    token, user = cp.login("admin@neurawall.local", "Admin-Password-1!")
    assert token and user.role == "admin"
    with pytest.raises(PolicyViolation):
        cp.login("admin@neurawall.local", "wrong")
    assert len(cp.list_rules()) == 7
    assert cp.latest_version() == 1
    assert cp.verify_audit() >= 2


def test_ingest_blocks_injection_and_creates_alert(cp):
    gen = TrafficGenerator(seed=5)
    warm(cp, gen)
    out = cp.ingest("n1", gen.scenario("sql_injection", 10))
    assert out.accepted == 10 and out.verdicts
    assert all(v.rule_id == "R-000001" and v.action == Action.DROP for v in out.verdicts)
    alerts, total = cp.list_alerts()
    assert total >= 1
    related = [a for a in alerts if "sql_injection" in a.labels]
    assert sum(a.flow_count for a in related) == 10
    # All flows of one source + threat form a single incident, blocked or not.
    assert len(related) == 1
    incident = related[0]
    assert incident.blocked_count == len(out.verdicts) and incident.flow_count == 10
    assert incident.tier3_pending


def test_tier3_triage_drafts_rule_and_approval_publishes_bundle(cp):
    gen = TrafficGenerator(seed=6)
    warm(cp, gen)
    cp.ingest("n1", gen.scenario("c2_beacon", 8))
    alert = next(a for a in cp.list_alerts()[0] if "c2_beacon" in a.labels)
    triaged = cp.triage_alert(alert.id)
    assert triaged.draft_id and not triaged.tier3_pending
    draft_row = cp.get_draft(triaged.draft_id)
    assert draft_row.data["simulation"]["flows_evaluated"] > 0
    rule = cp.approve_draft("approver@x", triaged.draft_id, mode=RuleMode.ENFORCE, note="confirmed")
    assert rule.approved_by == "approver@x" and rule.mode == RuleMode.ENFORCE
    assert cp.latest_version() == 2
    with pytest.raises(PolicyViolation):
        cp.approve_draft("approver@x", triaged.draft_id, mode=RuleMode.ENFORCE)
    assert cp.verify_audit() > 3


def test_blast_radius_gate(cp):
    gen = TrafficGenerator(seed=7)
    warm(cp, gen)
    from neurawall.core.models import DraftSource, RuleDraft

    broad = RuleDraft(
        name="block https",
        rationale="too broad",
        action=Action.DROP,
        match=RuleMatch(dst_ports=[443]),
        confidence=0.5,
        source=DraftSource.OPERATOR,
    )
    d = cp.create_draft(broad, actor="op@x")
    assert d.simulation.exceeds_threshold
    with pytest.raises(PolicyViolation, match="blast radius"):
        cp.approve_draft("admin@x", d.draft_id, mode=RuleMode.ENFORCE)
    rule = cp.approve_draft("admin@x", d.draft_id, mode=RuleMode.ALERT_ONLY)
    assert rule.mode == RuleMode.ALERT_ONLY


def test_four_eyes(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        auth={"bootstrap_admin_password": "Admin-Password-1!"},
        policy={"require_four_eyes": True},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    from neurawall.core.models import DraftSource, RuleDraft

    d = cp.create_draft(
        RuleDraft(
            name="x",
            rationale="y",
            action=Action.DROP,
            match=RuleMatch(dst_ports=[4444]),
            confidence=0.9,
            source=DraftSource.OPERATOR,
        ),
        actor="alice",
    )
    with pytest.raises(PolicyViolation, match="four-eyes"):
        cp.approve_draft("alice", d.draft_id, mode=RuleMode.ENFORCE)
    cp.approve_draft("bob", d.draft_id, mode=RuleMode.ENFORCE)
    cp.stop()


def test_node_enrollment_and_signed_bundle(cp):
    token = cp.create_enrollment_token("admin")
    node, api_key = cp.enroll_node(
        token, name="edge-1", hostname="h", agent_version="1", backend="dry-run"
    )
    with pytest.raises(PolicyViolation):
        cp.enroll_node(token, name="again", hostname="h", agent_version="1", backend="dry-run")
    assert cp.authenticate_node(api_key).id == node.id
    kid, pem = cp.public_key()
    env = cp.bundle_for_node(node.id)
    bundle = open_bundle(env, {kid: load_public_key(pem)})
    assert bundle.version == 1 and len(bundle.rules) == 7
    forged = SignedEnvelope.model_validate(sign_with_other_key(env))
    with pytest.raises(IntegrityFailure):
        open_bundle(forged, {kid: load_public_key(pem)})
    cp.revoke_node("admin", node.id)
    with pytest.raises(PolicyViolation):
        cp.authenticate_node(api_key)


def sign_with_other_key(env):
    from neurawall.security.integrity import sign_payload

    other = sign_payload(env.payload, EphemeralSigner())
    return {**other.model_dump(), "key_id": env.key_id}


def test_staged_rollout_advances_to_active(cp):
    cp.update_rule("admin", "R-000003", mode=RuleMode.ENFORCE)
    v = cp.latest_version()
    rows = {b.version: b for b in cp.list_bundles()}
    assert rows[v].status == "rolling_out" and rows[v].stage_index == 0
    cp.run_maintenance()
    cp.run_maintenance()
    assert {b.version: b for b in cp.list_bundles()}[v].status == "active"


def test_rule_update_and_hygiene(cp):
    r = cp.update_rule("admin", "R-000005", enabled=False)
    assert not r.enabled and r.version == 2
    assert isinstance(cp.hygiene(), list)


def test_last_admin_protected(cp):
    admin = cp.list_users()[0]
    with pytest.raises(PolicyViolation):
        cp.update_user("admin", admin.id, role=Role.VIEWER)
    u = cp.create_user(
        "admin", email="v@x.io", name="V", role=Role.VIEWER, password="Viewer-Pass-12"
    )
    assert u.must_change_password


def test_dashboard_and_explain(cp):
    gen = TrafficGenerator(seed=8)
    warm(cp, gen)
    cp.ingest("n1", gen.scenario("dga", 10))
    d = cp.dashboard()
    assert d["total_flows"] >= 310 and "dga" in d["labels"]
    with cp.db.session() as s:
        fid = s.query(db.FlowRow.flow_id).filter(db.FlowRow.labels.contains("dga")).first()[0]
    assert "explanation" in cp.explain_flow(fid)


def test_label_rule_blocks_enforced_c2_after_promotion(cp):
    cp.update_rule("admin", "R-000003", mode=RuleMode.ENFORCE)
    gen = TrafficGenerator(seed=9)
    warm(cp, gen)
    out = cp.ingest("n1", gen.scenario("c2_beacon", 5))
    assert out.verdicts and all(v.action == Action.QUARANTINE for v in out.verdicts)
    assert ThreatLabel.C2_BEACON in out.verdicts[0].labels


def test_rollback_restores_rules_as_new_version(cp):
    cp.update_rule("admin", "R-000005", enabled=False)  # v2
    assert not cp.get_rule("R-000005").enabled
    new = cp.rollback_bundle("admin", 2, "too noisy")
    assert new == 3 and cp.get_rule("R-000005").enabled
    statuses = {b.version: b.status for b in cp.list_bundles()}
    assert statuses[2] == "rolled_back" and statuses[3] == "active"
    assert cp.bundle_for_node("any-node").payload["version"] == 3


def test_triage_skips_enforced_and_dedupes_drafts(cp):
    gen = TrafficGenerator(seed=10)
    warm(cp, gen)
    cp.ingest("n1", gen.scenario("dns_tunnel", 6))
    cp.ingest("n1", gen.scenario("command_injection", 10))
    alerts = cp.list_alerts()[0]
    for a in alerts:
        cp.triage_alert(a.id)
    fully_blocked = [a for a in cp.list_alerts()[0] if a.blocked_count == a.flow_count]
    assert fully_blocked and all(a.draft_id is None for a in fully_blocked)
    matches = [str(d.data["match"]) for d in cp.list_drafts("pending")]
    assert len(matches) == len(set(matches))


def test_multi_use_enrollment_token(cp):
    token = cp.create_enrollment_token("admin", max_uses=2)
    a, _ = cp.enroll_node(token, name="a", hostname="", agent_version="1", backend="dry-run")
    b, _ = cp.enroll_node(token, name="b", hostname="", agent_version="1", backend="dry-run")
    assert a.id != b.id
    with pytest.raises(PolicyViolation):
        cp.enroll_node(token, name="c", hostname="", agent_version="1", backend="dry-run")


def test_migrations_are_idempotent_and_match_models(tmp_path):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from neurawall.services.control_plane.db import Base, Database, migrate

    database = Database(f"sqlite:///{tmp_path / 'm.db'}")
    migrate(database.engine)  # second run is a no-op
    with database.engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], diff


def test_bootstrap_password_file_removed_after_first_change(tmp_path):
    settings = load_settings(environment="test", data_dir=tmp_path)
    plane = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    f = tmp_path / "initial-admin-password.txt"
    assert f.exists() and oct(f.stat().st_mode & 0o777) == "0o600"
    assert oct(tmp_path.stat().st_mode & 0o777) == "0o700"
    email, password = f.read_text().split()
    _, user = plane.login(email, password)
    plane.change_password(user.id, password, "New-Admin-Pass-42")
    assert not f.exists()
    plane.stop()


def test_signing_key_rotation_republishes_bundle(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path,
        auth={"bootstrap_admin_password": "Admin-Password-1!"},
    )
    first = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    first.stop()
    rotated = EphemeralSigner()
    second = ControlPlane(settings, signer=rotated, advisor_backend=None)
    env = second.bundle_for_node("node-x")
    assert env.key_id == rotated.key_id and env.payload["version"] == 2
    second.stop()
