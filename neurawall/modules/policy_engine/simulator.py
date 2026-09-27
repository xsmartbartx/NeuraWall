"""Traffic replay against candidate rules: blast radius before presentation (blueprint §5.3)."""

from __future__ import annotations

from collections.abc import Iterable

from neurawall.core.models import Action, Evidence, RuleMatch, SimulationResult
from neurawall.modules.policy_engine.ruleset import match_flow

#: Flows with this much Tier 1 / Tier 2 suspicion are not counted as legitimate traffic.
SUSPICIOUS_SCORE = 0.8
SUSPICIOUS_LABEL_CONFIDENCE = 0.7


def is_legitimate(ev: Evidence) -> bool:
    if ev.anomaly is not None and ev.anomaly.score >= SUSPICIOUS_SCORE:
        return False
    return not any(c.confidence >= SUSPICIOUS_LABEL_CONFIDENCE for c in ev.malicious_labels)


def simulate(match: RuleMatch, action: Action, history: Iterable[Evidence], *,
             threshold: float) -> SimulationResult:
    evaluated = matched = legit_total = legit_matched = 0
    sources: set[str] = set()
    destinations: set[str] = set()
    samples: list[str] = []
    for ev in history:
        evaluated += 1
        legit = is_legitimate(ev)
        legit_total += legit
        if match_flow(match, ev):
            matched += 1
            legit_matched += legit
            sources.add(ev.flow.src_ip)
            destinations.add(ev.flow.dst_ip)
            if len(samples) < 20:
                samples.append(ev.flow.flow_id)
    blast = legit_matched / legit_total if legit_total else 0.0
    return SimulationResult(
        flows_evaluated=evaluated,
        flows_matched=matched,
        blast_radius=round(blast, 6),
        legitimate_matched=legit_matched,
        would_block=matched if action.is_blocking else 0,
        affected_sources=len(sources),
        affected_destinations=len(destinations),
        sample_matches=samples,
        exceeds_threshold=action.is_blocking and blast > threshold,
        threshold=threshold,
    )
