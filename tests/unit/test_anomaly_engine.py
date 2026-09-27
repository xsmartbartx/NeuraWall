import time

import numpy as np

from neurawall.modules.anomaly_engine import AnomalyEngine
from neurawall.modules.anomaly_engine.features import dns_label_entropy
from neurawall.modules.flow_collector.generator import TrafficGenerator


def _trained_engine(gen, n=1500):
    eng = AnomalyEngine(warmup_flows=300, trees=50)
    flows = [gen.benign() for _ in range(n)]
    for i in range(0, n, 100):
        eng.score_batch(flows[i:i + 100])
    return eng


def test_untrained_engine_is_low_confidence():
    eng = AnomalyEngine(warmup_flows=100)
    s = eng.score(TrafficGenerator(seed=1).benign())
    assert 0 <= s.score <= 1 and s.confidence < 0.1


def test_benign_scores_low_attacks_score_high():
    gen = TrafficGenerator(seed=3)
    eng = _trained_engine(gen)
    assert eng.trained
    benign = eng.score_batch([gen.benign() for _ in range(300)])
    fp_rate = np.mean([s.score >= 0.6 for s in benign])
    assert fp_rate < 0.05, fp_rate

    for scenario in ("exfiltration", "dga", "dns_tunnel", "port_scan"):
        scores = eng.score_batch(gen.scenario(scenario, 30))
        detected = np.mean([s.score >= 0.6 for s in scores])
        assert detected >= 0.5, (scenario, detected)
        assert any(s.top_features for s in scores)


def test_scores_are_bounded_and_attributed():
    gen = TrafficGenerator(seed=5)
    eng = _trained_engine(gen, 600)
    for s in eng.score_batch(gen.scenario("exfiltration", 10)):
        assert 0.0 <= s.score <= 1.0
        assert len(s.top_features) <= 3


def test_change_window_suppression():
    gen = TrafficGenerator(seed=9)
    eng = _trained_engine(gen, 600)
    flows = gen.scenario("dga", 20)
    eng.suppress([f"{flows[0].src_ip}/32"], seconds=60, reason="deploy")
    scores = eng.score_batch(flows)
    assert all(s.score <= 0.25 for s in scores)
    assert scores[0].top_features[0].feature == "change_window_suppression" or any(
        a.feature == "change_window_suppression" for a in scores[0].top_features)


def test_entropy():
    assert dns_label_entropy("www.google.com") < 2.5
    assert dns_label_entropy("x8f7k2qz9m1v0p3r.com") > 3.5


def test_batch_latency_budget():
    gen = TrafficGenerator(seed=11)
    eng = _trained_engine(gen, 800)
    flows = [gen.benign() for _ in range(500)]
    t = time.perf_counter()
    eng.score_batch(flows)
    per_flow_ms = (time.perf_counter() - t) * 1000 / len(flows)
    assert per_flow_ms < 1.0, per_flow_ms  # blueprint §5.1: < 1 ms per flow


def test_new_hosts_ramping_up_are_not_anomalous():
    """Regression: a per-host rate baseline flagged every new host during its first minute."""
    gen = TrafficGenerator(seed=17, hosts=40)
    eng = AnomalyEngine(warmup_flows=200, trees=50)
    novel_like = 0
    total = 0
    for _ in range(30):  # 30 batches of live-rate traffic
        scores = eng.score_batch([gen.benign() for _ in range(60)])
        novel_like += sum(s.score >= 0.8 for s in scores)
        total += len(scores)
    assert novel_like / total < 0.005, novel_like / total


def test_flood_from_one_source_is_detected():
    gen = TrafficGenerator(seed=18)
    eng = _trained_engine(gen, 1000)
    flood = gen.scenario("brute_force", 150)
    scores = eng.score_batch(flood)
    assert max(s.score for s in scores[-50:]) >= 0.8
