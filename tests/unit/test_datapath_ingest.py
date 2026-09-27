import json

from neurawall.core.models import Action, PolicyBundle, RuleMatch, RuleMode, ThreatLabel, Verdict
from neurawall.modules.datapath.backends import (
    DryRunBackend,
    compile_rule,
    is_static,
    render_ruleset,
)
from neurawall.modules.flow_collector.ingest import claimed_client, parse_flows, read_zeek_dir
from tests.conftest import make_flow, make_rule


def test_compile_static_rules():
    r = make_rule(1, match=RuleMatch(src_cidrs=["10.0.0.0/8", "2001:db8::/32"], dst_ports=[22],
                                     protocols=["tcp"]))
    lines = compile_rule(r)
    assert any(line.startswith("ip saddr { 10.0.0.0/8 }") and "tcp dport { 22 }" in line
               for line in lines)
    assert any(line.startswith("ip6 saddr { 2001:db8::/32 }") for line in lines)
    assert all('comment "R-000001"' in line for line in lines)


def test_render_only_enforced_static_rules():
    static = make_rule(1, match=RuleMatch(dst_ports=[23]))
    label = make_rule(2, match=RuleMatch(labels=[ThreatLabel.DGA]))
    alert_only = make_rule(3, mode=RuleMode.ALERT_ONLY, match=RuleMatch(dst_ports=[25]))
    text = render_ruleset(PolicyBundle(version=2, rules=[static, label, alert_only]))
    assert "R-000001" in text and "R-000002" not in text and "R-000003" not in text
    assert text.count("jump enforce") == 2
    assert is_static(static) and not is_static(label)


def test_dry_run_backend_applies_and_caches():
    be = DryRunBackend()
    res = be.apply_bundle(PolicyBundle(version=3, rules=[make_rule(1), make_rule(
        2, match=RuleMatch(labels=[ThreatLabel.DGA]))]))
    assert res.ok and res.static_rules == 1 and res.dynamic_rules == 1
    f = make_flow()
    assert not be.apply_verdict(f, Verdict(flow_id=f.flow_id, action=Action.ALERT, enforced=False))
    assert be.apply_verdict(f, Verdict(flow_id=f.flow_id, action=Action.DROP, enforced=True,
                                       rule_id="R-000002"))
    assert be.cache.get(f) == (Action.DROP, "R-000002")
    assert be.state().applied_version == 3 and be.state().active_blocks == 1


def test_parse_flows_counts_malformed():
    res = parse_flows([{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, {"src_ip": "bad"}, "x"],
                      node_id="n1")
    assert len(res.flows) == 1 and res.rejected == 2 and res.flows[0].node_id == "n1"


def test_zeek_join(tmp_path):
    conn = {"ts": 1700000000.5, "uid": "C1", "id.orig_h": "10.0.0.5", "id.orig_p": 50000,
            "id.resp_h": "93.184.216.34", "id.resp_p": 443, "proto": "tcp", "duration": 1.2,
            "orig_ip_bytes": 900, "resp_ip_bytes": 5000, "orig_pkts": 8, "resp_pkts": 9,
            "local_orig": True, "local_resp": False, "history": "ShADadFf"}
    dns_conn = {**conn, "uid": "C2", "proto": "udp", "id.resp_p": 53}
    ssl = {"uid": "C1", "server_name": "example.com", "version": "TLSv13",
           "ja3": "cd08e31494f9531f560d64c695473da9"}
    dns = {"uid": "C2", "query": "example.com", "qtype_name": "A", "rcode_name": "NOERROR"}
    (tmp_path / "conn.log").write_text("\n".join(json.dumps(x) for x in [conn, dns_conn]) + "\n{bad\n")
    (tmp_path / "ssl.log").write_text(json.dumps(ssl))
    (tmp_path / "dns.log").write_text(json.dumps(dns))
    res = read_zeek_dir(tmp_path, node_id="sensor-1")
    assert len(res.flows) == 2
    tls_flow = next(f for f in res.flows if f.flow_id == "C1")
    assert tls_flow.sni == "example.com" and tls_flow.direction == "outbound"
    assert next(f for f in res.flows if f.flow_id == "C2").dns_qname == "example.com"


def test_claimed_client():
    assert claimed_client("Mozilla/5.0 ... Chrome/128.0 Safari/537.36") == "chrome"
    assert claimed_client("Mozilla/5.0 ... Chrome/128.0 Edg/128.0") == "edge"
    assert claimed_client("curl/8.0") is None


def test_direction_rules_are_not_compiled_statically():
    inbound = make_rule(9, match=RuleMatch(directions=["inbound"], dst_ports=[23]))
    assert not is_static(inbound)
    assert "R-000009" not in render_ruleset(PolicyBundle(version=1, rules=[inbound]))
