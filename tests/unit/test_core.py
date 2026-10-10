import json
import logging

import pytest
from pydantic import ValidationError

from neurawall.core.config import load_settings
from neurawall.core.errors import ModelFault
from neurawall.core.logging import JsonFormatter, RedactionFilter, get_logger, redact, redact_text
from neurawall.core.models import (
    Action,
    FlowRecord,
    L7Meta,
    Rule,
    RuleMatch,
    TlsMeta,
    Verdict,
)
from neurawall.core.telemetry import Registry
from neurawall.core.validation import check_probability, domain_matches_suffix, ip_in_any


def test_flow_record_validates_ips_and_bounds():
    f = FlowRecord(src_ip="10.0.0.1", dst_ip="2001:db8::1", dst_port=443)
    assert f.dst_ip == "2001:db8::1"
    with pytest.raises(ValidationError):
        FlowRecord(src_ip="10.0.0.999", dst_ip="1.1.1.1")
    with pytest.raises(ValidationError):
        FlowRecord(src_ip="10.0.0.1", dst_ip="1.1.1.1", dst_port=70000)
    with pytest.raises(ValidationError):
        FlowRecord(src_ip="10.0.0.1", dst_ip="1.1.1.1", unknown_field=1)


def test_flow_record_is_frozen():
    f = FlowRecord(src_ip="10.0.0.1", dst_ip="1.1.1.1")
    with pytest.raises(ValidationError):
        f.dst_port = 1  # type: ignore[misc]


def test_domain_normalisation():
    f = FlowRecord(src_ip="10.0.0.1", dst_ip="1.1.1.1", l7=L7Meta(tls=TlsMeta(sni="Example.COM.")))
    assert f.sni == "example.com"
    with pytest.raises(ValidationError):
        TlsMeta(sni="bad domain!")


def test_rule_match_requires_criterion():
    with pytest.raises(ValidationError):
        RuleMatch()
    assert RuleMatch(dst_ports=[22]).dst_ports == [22]


def test_rule_requires_rationale():
    with pytest.raises(ValidationError):
        Rule(
            id="R-000001",
            name="x",
            rationale="",
            action=Action.DROP,
            match=RuleMatch(dst_ports=[1]),
        )
    with pytest.raises(ValidationError):
        Rule(id="bad", name="x", rationale="r", action=Action.DROP, match=RuleMatch(dst_ports=[1]))


def test_enforced_blocking_verdict_needs_rule_id():
    with pytest.raises(ValidationError):
        Verdict(flow_id="f", action=Action.DROP, enforced=True)
    assert Verdict(flow_id="f", action=Action.DROP, enforced=True, rule_id="R-000001").rule_id


def test_probability_check():
    assert check_probability(0.5, what="s") == 0.5
    for bad in (1.5, -0.1, float("nan")):
        with pytest.raises(ModelFault):
            check_probability(bad, what="s")


def test_matching_helpers():
    assert ip_in_any("10.1.2.3", ["10.0.0.0/8"])
    assert not ip_in_any("10.1.2.3", ["2001:db8::/32"])
    assert domain_matches_suffix("a.evil.com", ["evil.com"])
    assert domain_matches_suffix("evil.com", ["evil.com"])
    assert not domain_matches_suffix("notevil.com", ["evil.com"])


def test_redaction():
    assert redact({"Authorization": "Bearer abc", "user": "bob"}) == {
        "Authorization": "[REDACTED]",
        "user": "bob",
    }
    assert "abc123" not in redact_text("GET /login?token=abc123 HTTP/1.1")
    assert "sk-ant-" not in redact_text("key sk-ant-api03-abcdefghijklmnop")
    for key in (
        "nx_live_abcdef123456",
        "nwk_Zm9vYmFyYmF6",
        "nwe_Zm9vYmFyYmF6",
        "whsec_0123456789abcdef",
    ):
        assert key not in redact_text(f"call failed for {key} at 12:00")
    assert redact({"nested": {"password": "x"}})["nested"]["password"] == "[REDACTED]"


def test_logger_redacts_fields(capsys):
    record = logging.LogRecord(
        "t", logging.INFO, __file__, 1, "call https://x.io/a?k=v", None, None
    )
    record.fields = {"api_key": "secret", "path": "/p?q=1"}
    RedactionFilter().filter(record)
    doc = json.loads(JsonFormatter().format(record))
    assert doc["fields"]["api_key"] == "[REDACTED]"
    assert "k=v" not in doc["msg"]
    assert "q=1" not in doc["fields"]["path"]
    get_logger("x").info("ok", a=1)  # adapter does not raise


def test_config_rejects_unknown_keys_and_layers(monkeypatch, tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("port: 9000\nllm:\n  model: from-file\n")
    monkeypatch.setenv("NEURAWALL_CONFIG", str(cfg))
    monkeypatch.setenv("NEURAWALL_LLM__MODEL", "from-env")
    s = load_settings()
    assert s.port == 9000 and s.llm.model == "from-env"
    assert load_settings(port=9100).port == 9100
    cfg.write_text("bogus: 1\n")
    with pytest.raises(ValidationError):
        load_settings()


def test_production_requires_secret(monkeypatch):
    monkeypatch.delenv("NEURAWALL_CONFIG", raising=False)
    with pytest.raises(ValidationError):
        load_settings(environment="production")


def test_metrics_exposition():
    r = Registry()
    r.counter("flows_total", "flows").inc(node="a")
    r.histogram("lat_seconds", "lat").observe(0.002)
    text = r.expose()
    assert 'flows_total{node="a"} 1.0' in text
    assert "lat_seconds_count 1" in text
