import pytest

from neurawall.core.errors import IntegrityFailure
from neurawall.core.models import (
    Action,
    AnomalyScore,
    PolicyBundle,
    RuleMatch,
    RuleMode,
    ThreatLabel,
)
from neurawall.modules.policy_engine import (
    Evidence,
    PolicyEngine,
    RolloutState,
    analyze_hygiene,
    open_bundle,
    should_rollback,
    sign_bundle,
    simulate,
)
from neurawall.security.integrity import EphemeralSigner, load_public_key
from tests.conftest import classification, make_flow, make_rule


def engine(*rules, **kw):
    return PolicyEngine(PolicyBundle(version=1, rules=list(rules), **kw))


def test_first_matching_rule_by_priority_wins():
    allow = make_rule(
        1, action=Action.ALLOW, priority=10, match=RuleMatch(src_cidrs=["10.0.0.0/24"])
    )
    drop = make_rule(2, action=Action.DROP, priority=20, match=RuleMatch(dst_ports=[443]))
    v = engine(drop, allow).evaluate(Evidence(flow=make_flow()))
    assert v.action == Action.ALLOW and v.rule_id == "R-000001" and not v.enforced


def test_enforced_drop_carries_rule_id():
    v = engine(make_rule(7, match=RuleMatch(dst_ports=[443]))).evaluate(Evidence(flow=make_flow()))
    assert v.action == Action.DROP and v.enforced and v.rule_id == "R-000007"


def test_alert_only_rule_never_enforces():
    r = make_rule(3, mode=RuleMode.ALERT_ONLY, match=RuleMatch(dst_ports=[443]))
    v = engine(r).evaluate(Evidence(flow=make_flow()))
    assert v.action == Action.ALERT and not v.enforced and v.rule_id == "R-000003"


def test_models_alone_cannot_block():
    f = make_flow()
    ev = Evidence(
        flow=f,
        anomaly=AnomalyScore(flow_id=f.flow_id, score=0.99, confidence=1.0),
        classifications=(classification(f.flow_id, ThreatLabel.C2_BEACON, 0.99),),
    )
    v = engine(make_rule(1, match=RuleMatch(dst_ports=[22]))).evaluate(ev)
    assert v.action == Action.ALERT and not v.enforced and v.rule_id is None


def test_label_rule_blocks_on_confident_classification():
    r = make_rule(5, match=RuleMatch(labels=[ThreatLabel.SQL_INJECTION], min_label_confidence=0.8))
    f = make_flow()
    weak = Evidence(
        flow=f, classifications=(classification(f.flow_id, ThreatLabel.SQL_INJECTION, 0.5),)
    )
    strong = Evidence(
        flow=f, classifications=(classification(f.flow_id, ThreatLabel.SQL_INJECTION, 0.9),)
    )
    assert engine(r).evaluate(weak).action == Action.ALLOW
    assert engine(r).evaluate(strong).action == Action.DROP


def test_l7_matchers():
    f = make_flow(tls={"sni": "cdn.evil.example"}, http={"path": "/admin/login"})
    assert (
        engine(make_rule(1, match=RuleMatch(sni_suffixes=["evil.example"])))
        .evaluate(Evidence(flow=f))
        .action
        == Action.DROP
    )
    assert (
        engine(make_rule(1, match=RuleMatch(http_path_prefixes=["/admin"])))
        .evaluate(Evidence(flow=f))
        .action
        == Action.DROP
    )
    assert (
        engine(make_rule(1, match=RuleMatch(dns_suffixes=["evil.example"])))
        .evaluate(Evidence(flow=f))
        .action
        == Action.ALLOW
    )


def test_simulation_blast_radius():
    history = [Evidence(flow=make_flow(dst_port=443 if i < 3 else 80)) for i in range(100)]
    res = simulate(RuleMatch(dst_ports=[443]), Action.DROP, history, threshold=0.01)
    assert res.flows_matched == 3 and res.blast_radius == 0.03 and res.exceeds_threshold
    res = simulate(RuleMatch(dst_ports=[443]), Action.ALERT, history, threshold=0.01)
    assert not res.exceeds_threshold and res.would_block == 0


def test_hygiene_detects_shadow_redundant_broad():
    broad = make_rule(1, priority=10, match=RuleMatch(dst_ports=[22, 23]))
    shadowed = make_rule(
        2,
        priority=20,
        action=Action.ALLOW,
        match=RuleMatch(dst_ports=[22], src_cidrs=["10.0.0.0/8"]),
    )
    redundant = make_rule(3, priority=30, match=RuleMatch(dst_ports=[23]))
    everything = make_rule(4, priority=40, match=RuleMatch(protocols=["tcp"]))
    kinds = {(f.rule_id, f.kind) for f in analyze_hygiene([broad, shadowed, redundant, everything])}
    assert ("R-000002", "shadowed") in kinds
    assert ("R-000003", "redundant") in kinds
    assert ("R-000004", "overly_broad") in kinds


def test_bundle_signing_and_anti_rollback():
    s = EphemeralSigner()
    keys = {s.key_id: load_public_key(s.public_key_pem())}
    env = sign_bundle(PolicyBundle(version=4, rules=[make_rule(1)]), s)
    assert open_bundle(env, keys).version == 4
    with pytest.raises(IntegrityFailure):
        open_bundle(env, keys, min_version=5)
    tampered = env.model_copy(update={"payload": {**env.payload, "default_action": "alert"}})
    with pytest.raises(IntegrityFailure):
        open_bundle(tampered, keys)


def test_rollout_stages():
    st = RolloutState(version=9, stage_index=0)
    nodes = [f"node-{i}" for i in range(2000)]
    canary = sum(st.includes(n) for n in nodes) / len(nodes)
    assert 0.02 < canary < 0.09
    full = st.advance().advance()
    assert full.complete and all(full.includes(n) for n in nodes)
    assert should_rollback(baseline_block_rate=0.01, canary_block_rate=0.05)
    assert not should_rollback(baseline_block_rate=0.01, canary_block_rate=0.015)
