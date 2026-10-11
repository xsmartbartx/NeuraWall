"""Deterministic offline advisor.

Used when no LLM is configured, when the Tier 3 budget is exhausted, or when the LLM
is unavailable (degraded mode). Produces the same structured outputs so the console
and approval workflow behave identically — only ``source`` differs.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass

from neurawall.core.models import Evidence, Rule, ThreatLabel, Verdict
from neurawall.modules.llm_advisor import schemas

_GENERIC_DESC = "anomalous traffic"
_SEVERITY = {
    ThreatLabel.EXFILTRATION: "critical",
    ThreatLabel.C2_BEACON: "critical",
    ThreatLabel.COMMAND_INJECTION: "critical",
    ThreatLabel.DNS_TUNNEL: "high",
    ThreatLabel.SQL_INJECTION: "high",
    ThreatLabel.TEMPLATE_INJECTION: "high",
    ThreatLabel.DGA: "high",
    ThreatLabel.PATH_TRAVERSAL: "high",
    ThreatLabel.XSS: "medium",
    ThreatLabel.TLS_MISMATCH: "medium",
    ThreatLabel.NOVEL: "medium",
}
_DESCRIPTIONS = {
    ThreatLabel.SQL_INJECTION: "SQL injection attempts against a web application",
    ThreatLabel.COMMAND_INJECTION: "OS command injection attempts against a web application",
    ThreatLabel.TEMPLATE_INJECTION: "server-side template / expression injection attempts",
    ThreatLabel.PATH_TRAVERSAL: "path traversal attempts to read files outside the web root",
    ThreatLabel.XSS: "cross-site scripting payloads in requests",
    ThreatLabel.DGA: "DNS lookups for algorithmically generated domains (likely malware)",
    ThreatLabel.DNS_TUNNEL: "data encoded into DNS queries (DNS tunnelling)",
    ThreatLabel.C2_BEACON: "periodic low-jitter callbacks consistent with command-and-control beaconing",
    ThreatLabel.EXFILTRATION: "large, asymmetric outbound transfers consistent with data exfiltration",
    ThreatLabel.TLS_MISMATCH: "a TLS client fingerprint that contradicts the claimed browser",
    ThreatLabel.NOVEL: "statistically anomalous traffic not explained by any known detector",
}
_ACTIONS = {
    "critical": [
        "Isolate the affected internal host(s) and start incident response.",
        "Approve the drafted blocking rule after reviewing its blast radius.",
        "Collect endpoint telemetry from the source host.",
    ],
    "high": [
        "Review the drafted rule and approve it in enforce mode if the simulation is clean.",
        "Check the targeted service's logs for successful exploitation.",
    ],
    "medium": ["Keep the drafted rule in alert-only mode and monitor for recurrence."],
    "low": ["No action required; continue monitoring."],
}


def _registrable(name: str) -> str:
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def _dominant(evs: list[Evidence]) -> tuple[ThreatLabel | None, float]:
    best: dict[ThreatLabel, float] = {}
    for ev in evs:
        for c in ev.malicious_labels:
            best[c.label] = max(best.get(c.label, 0.0), c.confidence)
    if not best:
        return None, 0.0
    label = max(
        best,
        key=lambda k: (Counter(c.label for ev in evs for c in ev.malicious_labels)[k], best[k]),
    )
    return label, best[label]


def _empty_match() -> schemas.LlmRuleMatch:
    return schemas.LlmRuleMatch(
        src_cidrs=[],
        dst_cidrs=[],
        dst_ports=[],
        protocols=[],
        sni_suffixes=[],
        dns_suffixes=[],
        http_path_prefixes=[],
        ja3=[],
        labels=[],
        min_label_confidence=0.0,
        min_anomaly_score=None,
    )


def _host(ip: str) -> str:
    return f"{ip}/128" if ":" in ip else f"{ip}/32"


_INJECTION_LABELS = (
    ThreatLabel.SQL_INJECTION,
    ThreatLabel.COMMAND_INJECTION,
    ThreatLabel.TEMPLATE_INJECTION,
    ThreatLabel.PATH_TRAVERSAL,
    ThreatLabel.XSS,
)


@dataclass
class _Indicators:
    evs: list[Evidence]
    dsts: Counter[str]
    ports: Counter[int]
    top_src: str
    top_dst: str


def _draft_injection(label: ThreatLabel, ind: _Indicators) -> tuple[schemas.LlmRuleMatch, str, str]:
    m = _empty_match()
    m.labels = [label.value]
    m.min_label_confidence = 0.8
    m.dst_cidrs = [_host(d) for d, _ in ind.dsts.most_common(4)]
    return m, "drop", f"Block {label.value.replace('_', ' ')} to {ind.top_dst}"


def _draft_dns(label: ThreatLabel, ind: _Indicators) -> tuple[schemas.LlmRuleMatch, str, str]:
    m = _empty_match()
    names = [ev.flow.dns_qname for ev in ind.evs if ev.flow.dns_qname]
    if label == ThreatLabel.DNS_TUNNEL and names:
        m.dns_suffixes = sorted({_registrable(n) for n in names})[:8]
        return m, "drop", f"Block DNS tunnel via {m.dns_suffixes[0]}"
    m.labels = [label.value]
    m.min_label_confidence = 0.8
    m.src_cidrs = [_host(ind.top_src)]
    return m, "quarantine", f"Quarantine DGA-infected host {ind.top_src}"


def _draft_channel(label: ThreatLabel, ind: _Indicators) -> tuple[schemas.LlmRuleMatch, str, str]:
    m = _empty_match()
    m.dst_cidrs = [_host(d) for d, _ in ind.dsts.most_common(4)]
    snis = sorted({ev.flow.sni for ev in ind.evs if ev.flow.sni})
    if snis:
        m.sni_suffixes = snis[:4]
    what = "C2 channel" if label == ThreatLabel.C2_BEACON else "exfiltration"
    return m, "drop", f"Block {what} to {ind.top_dst}"


def _draft_tls_mismatch(
    label: ThreatLabel, ind: _Indicators
) -> tuple[schemas.LlmRuleMatch, str, str]:
    m = _empty_match()
    ja3 = sorted(
        {
            ev.flow.l7.tls.ja3
            for ev in ind.evs
            if ev.flow.l7 and ev.flow.l7.tls and ev.flow.l7.tls.ja3
        }
    )
    m.ja3 = ja3[:4]
    m.labels = [label.value]
    return m, "alert", "Alert on spoofed browser TLS fingerprint"


def _draft_novel(ind: _Indicators) -> tuple[schemas.LlmRuleMatch, str, str]:
    """Novel / anomaly-only: narrowest scope that covers the evidence."""
    m = _empty_match()
    m.src_cidrs = [_host(ind.top_src)]
    if len(ind.ports) <= 3:
        m.dst_ports = sorted(ind.ports)
    m.min_anomaly_score = 0.8
    return m, "rate_limit", f"Rate-limit anomalous traffic from {ind.top_src}"


def draft_rule(evs: list[Evidence], rules: list[Rule]) -> schemas.LlmRuleDraft:
    label, conf = _dominant(evs)
    srcs = Counter(ev.flow.src_ip for ev in evs)
    dsts = Counter(ev.flow.dst_ip for ev in evs)
    ports = Counter(ev.flow.dst_port for ev in evs)
    top_src, top_dst = srcs.most_common(1)[0][0], dsts.most_common(1)[0][0]
    ind = _Indicators(evs, dsts, ports, top_src, top_dst)
    if label in _INJECTION_LABELS:
        m, action, name = _draft_injection(label, ind)
    elif label in (ThreatLabel.DGA, ThreatLabel.DNS_TUNNEL):
        m, action, name = _draft_dns(label, ind)
    elif label in (ThreatLabel.C2_BEACON, ThreatLabel.EXFILTRATION):
        m, action, name = _draft_channel(label, ind)
    elif label == ThreatLabel.TLS_MISMATCH:
        m, action, name = _draft_tls_mismatch(label, ind)
    else:
        m, action, name = _draft_novel(ind)
        conf = max((ev.anomaly.score for ev in evs if ev.anomaly), default=0.5) * 0.7

    covered = [r.id for r in rules if r.enabled and r.action.value == action]
    desc = _DESCRIPTIONS.get(label, _GENERIC_DESC) if label else _GENERIC_DESC
    rationale = (
        f"{len(evs)} flow(s) show {desc}. Sources: {', '.join(s for s, _ in srcs.most_common(3))}; "
        f"destinations: {', '.join(d for d, _ in dsts.most_common(3))}. "
        f"The proposed match is scoped to the observed indicators to minimise blast radius. "
        f"{len(covered)} existing rule(s) already use action '{action}'; none covers these "
        f"indicators. Generated by the offline heuristic advisor."
    )
    return schemas.LlmRuleDraft(
        threat_assessment=desc,
        name=name[:120],
        rationale=rationale,
        action=action,  # type: ignore[arg-type]
        priority=200,
        match=m,
        confidence=round(min(conf or 0.5, 0.95), 3),
    )


def summarize(evs: list[Evidence]) -> schemas.LlmAlertSummary:
    label, conf = _dominant(evs)
    if label:
        severity = _SEVERITY.get(label, "low")
    elif any(ev.anomaly and ev.anomaly.score >= 0.8 for ev in evs):
        severity = "medium"
    else:
        severity = "low"
    srcs = sorted({ev.flow.src_ip for ev in evs})
    dsts = sorted({ev.flow.dst_ip for ev in evs})
    desc = _DESCRIPTIONS.get(label, _GENERIC_DESC) if label else _GENERIC_DESC
    title = (
        f"{label.value.replace('_', ' ').title() if label else 'Anomalous traffic'}: "
        f"{srcs[0]} → {dsts[0]}" + (f" (+{len(dsts) - 1})" if len(dsts) > 1 else "")
    )
    summary = (
        f"{len(evs)} related flow(s) indicate {desc}"
        + (f" (peak detector confidence {conf:.0%})" if label else "")
        + ". "
        f"{len(srcs)} source(s) and {len(dsts)} destination(s) are involved."
    )
    return schemas.LlmAlertSummary(
        title=title[:200],
        summary=summary,
        severity=severity,  # type: ignore[arg-type]
        recommended_actions=_ACTIONS[severity],
    )


def narrate(evs: list[Evidence]) -> schemas.LlmIncidentNarrative:
    ordered = sorted(evs, key=lambda e: e.flow.ts_start)
    timeline = []
    for ev in ordered[:40]:
        f = ev.flow
        labels = ", ".join(c.label.value for c in ev.malicious_labels) or "no label"
        timeline.append(
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(f.ts_start))}Z "
            f"{f.src_ip} → {f.dst_ip}:{f.dst_port}/{f.protocol.value} "
            f"({f.bytes_out}B out) — {labels}"
            + (f", anomaly {ev.anomaly.score:.2f}" if ev.anomaly else "")
        )
    s = summarize(evs)
    span = ordered[-1].flow.ts_start - ordered[0].flow.ts_start if ordered else 0
    narrative = (
        f"{s.summary} The activity spans {span / 60:.1f} minute(s), starting at "
        f"{timeline[0].split(' ')[1] if timeline else 'n/a'} UTC. "
        "Review the timeline below for the ordered sequence of flows."
    )
    return schemas.LlmIncidentNarrative(title=s.title, narrative=narrative, timeline=timeline)


def explain(verdict: Verdict, rule: Rule | None, ev: Evidence | None) -> schemas.LlmExplanation:
    if rule is None:
        text = (
            f"This flow was {verdict.action.value}ed by the default policy; no rule matched. "
            if verdict.action.value != "alert"
            else "No rule matched, but inference signals exceeded the alert threshold, so an alert "
            "was raised. Models alone never block traffic. "
        )
    else:
        mode = "was enforced" if verdict.enforced else "was reported but not enforced (alert-only)"
        text = (
            f"Rule {rule.id} '{rule.name}' matched this flow and its '{rule.action.value}' action "
            f"{mode}. Rule rationale: {rule.rationale} "
        )
    if verdict.reasons:
        text += "Signals: " + "; ".join(verdict.reasons) + "."
    return schemas.LlmExplanation(explanation=text)
