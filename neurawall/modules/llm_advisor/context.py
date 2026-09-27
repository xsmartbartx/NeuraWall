"""Context assembly: turn evidence into a bounded, model-readable bundle."""

from __future__ import annotations

from typing import Any

from neurawall.core.models import Evidence, Rule, Verdict


def flow_context(ev: Evidence) -> dict[str, Any]:
    f = ev.flow
    doc: dict[str, Any] = {
        "flow_id": f.flow_id,
        "node": f.node_id,
        "ts": round(f.ts_start, 3),
        "src": f"{f.src_ip}:{f.src_port}",
        "dst": f"{f.dst_ip}:{f.dst_port}",
        "protocol": f.protocol.value,
        "direction": f.direction.value,
        "bytes_out": f.bytes_out,
        "bytes_in": f.bytes_in,
        "packets_out": f.packets_out,
        "packets_in": f.packets_in,
        "duration_s": round(f.duration, 3),
    }
    if f.inter_arrival_ms:
        doc["inter_arrival_ms_sample"] = [round(x) for x in f.inter_arrival_ms[:12]]
    if f.l7:
        if f.l7.http:
            h = f.l7.http
            doc["http"] = {
                "method": h.method,
                "host": h.host,
                "path": h.path,
                "user_agent": h.user_agent,
                "status": h.status,
            }
        if f.l7.dns:
            d = f.l7.dns
            doc["dns"] = {"qname": d.qname, "qtype": d.qtype, "rcode": d.rcode}
        if f.l7.tls:
            t = f.l7.tls
            doc["tls"] = {
                "sni": t.sni,
                "ja3": t.ja3,
                "version": t.version,
                "claimed_client": t.claimed_client,
            }
    if ev.anomaly:
        doc["tier1"] = {
            "score": ev.anomaly.score,
            "confidence": ev.anomaly.confidence,
            "top_features": [a.feature for a in ev.anomaly.top_features],
        }
    if ev.classifications:
        doc["tier2"] = [
            {
                "label": c.label.value,
                "confidence": c.confidence,
                "detector": c.detector,
                "evidence": [f"{a.feature}={a.value}" for a in c.attributions[:4]],
            }
            for c in ev.classifications
        ]
    return doc


def rules_context(rules: list[Rule], limit: int = 40) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "name": r.name,
            "action": r.action.value,
            "mode": r.mode.value,
            "priority": r.priority,
            "match": r.match.model_dump(mode="json", exclude_defaults=True),
        }
        for r in sorted(rules, key=lambda r: r.priority)[:limit]
    ]


def verdict_context(v: Verdict) -> dict[str, Any]:
    return {
        "action": v.action.value,
        "rule_id": v.rule_id,
        "enforced": v.enforced,
        "reasons": v.reasons,
        "anomaly_score": v.anomaly_score,
        "labels": [x.value for x in v.labels],
    }
