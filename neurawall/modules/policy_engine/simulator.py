"""Traffic replay against candidate rules: blast radius before presentation (blueprint §5.3)."""

from __future__ import annotations

from collections.abc import Iterable

from neurawall.core.models import Action, RuleMatch, SimulationResult
from neurawall.modules.policy_engine.ruleset import Evidence, match_flow


def simulate(match: RuleMatch, action: Action, history: Iterable[Evidence], *,
             threshold: float) -> SimulationResult:
    evaluated = matched = 0
    sources: set[str] = set()
    destinations: set[str] = set()
    samples: list[str] = []
    for ev in history:
        evaluated += 1
        if match_flow(match, ev):
            matched += 1
            sources.add(ev.flow.src_ip)
            destinations.add(ev.flow.dst_ip)
            if len(samples) < 20:
                samples.append(ev.flow.flow_id)
    blast = matched / evaluated if evaluated else 0.0
    return SimulationResult(
        flows_evaluated=evaluated,
        flows_matched=matched,
        blast_radius=round(blast, 6),
        would_block=matched if action.is_blocking else 0,
        affected_sources=len(sources),
        affected_destinations=len(destinations),
        sample_matches=samples,
        exceeds_threshold=action.is_blocking and blast > threshold,
        threshold=threshold,
    )
