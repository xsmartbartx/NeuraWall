import pytest

from neurawall.core.models import (
    Action,
    Classification,
    DnsMeta,
    FlowRecord,
    HttpMeta,
    L7Meta,
    Rule,
    RuleMatch,
    ThreatLabel,
    TlsMeta,
)


def make_flow(**kw) -> FlowRecord:
    base = {"src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "src_port": 51000, "dst_port": 443,
            "bytes_out": 800, "bytes_in": 5000, "packets_out": 8, "packets_in": 9}
    http = kw.pop("http", None)
    dns = kw.pop("dns", None)
    tls = kw.pop("tls", None)
    if http or dns or tls:
        kw["l7"] = L7Meta(
            http=HttpMeta(**http) if http else None,
            dns=DnsMeta(**dns) if dns else None,
            tls=TlsMeta(**tls) if tls else None,
        )
    return FlowRecord(**{**base, **kw})


def make_rule(n: int = 1, **kw) -> Rule:
    match = kw.pop("match", None) or RuleMatch(dst_ports=[22])
    base = {"id": f"R-{n:06d}", "name": f"rule {n}", "rationale": "test", "action": Action.DROP,
            "match": match}
    return Rule(**{**base, **kw})


def classification(flow_id: str, label: ThreatLabel, conf: float = 0.95) -> Classification:
    return Classification(flow_id=flow_id, label=label, confidence=conf, detector="test")


@pytest.fixture
def flow_factory():
    return make_flow
