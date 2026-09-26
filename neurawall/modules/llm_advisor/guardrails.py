"""Tier 3 guardrails (blueprint §5.3, §9.2).

Input side: every byte of flow content is untrusted. It is serialised as JSON, bounded,
stripped of anything that could close the delimiting tag, and scanned for prompt-
injection markers (which are *reported to the model as evidence*, never obeyed).

Output side: the model's structured output is re-validated against the strict core
schemas. Anything that fails is discarded — no free-form field reaches the policy store.
"""

from __future__ import annotations

import json
import re
from typing import Any

from neurawall.core.errors import ValidationFailure
from neurawall.core.logging import redact
from neurawall.core.models import (
    Action,
    AlertSummary,
    DraftSource,
    IncidentNarrative,
    RuleDraft,
    RuleMatch,
    RuleMode,
    Severity,
    ThreatLabel,
)
from neurawall.modules.llm_advisor import schemas

UNTRUSTED_TAG = "untrusted_flow_data"
_TAG_BREAK = re.compile(r"</?\s*untrusted[_\s-]*flow[_\s-]*data\s*>", re.I)
_INJECTION_MARKERS = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|rules)|disregard .{0,20}instructions|"
    r"you are now|system prompt|new instructions:|act as|<\s*/?\s*(system|assistant|instructions)\s*>|"
    r"approve this rule|allow all traffic|whitelist)",
    re.I,
)
MAX_CONTEXT_CHARS = 60_000


def neutralise(value: Any) -> Any:
    """Recursively scrub strings so they cannot escape the untrusted-data envelope."""
    if isinstance(value, dict):
        return {str(k)[:64]: neutralise(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [neutralise(v) for v in value[:200]]
    if isinstance(value, str):
        return _TAG_BREAK.sub("[tag-removed]", value)[:2048]
    return value


def injection_markers(value: Any) -> list[str]:
    found: set[str] = set()

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list | tuple):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            found.update(m.group(0).lower()[:60] for m in _INJECTION_MARKERS.finditer(v))

    walk(value)
    return sorted(found)[:10]


def wrap_untrusted(payload: Any) -> str:
    clean = neutralise(redact(payload))
    text = json.dumps(clean, indent=1, default=str)
    if len(text) > MAX_CONTEXT_CHARS:
        text = text[:MAX_CONTEXT_CHARS] + "\n…[context truncated]"
    return f"<{UNTRUSTED_TAG}>\n{text}\n</{UNTRUSTED_TAG}>"


# ---------------------------------------------------------------------------
# Output validation
# ---------------------------------------------------------------------------


def _clamp(x: float) -> float:
    return min(max(float(x), 0.0), 1.0)


def to_rule_draft(out: schemas.LlmRuleDraft, *, source: DraftSource,
                  evidence_flow_ids: list[str]) -> RuleDraft:
    try:
        action = Action(out.action)
        labels = [ThreatLabel(x) for x in out.match.labels if x in ThreatLabel.__members__.values()]
        match = RuleMatch(
            src_cidrs=out.match.src_cidrs[:64],
            dst_cidrs=out.match.dst_cidrs[:64],
            dst_ports=out.match.dst_ports[:32],
            protocols=[p for p in out.match.protocols if p in ("tcp", "udp", "icmp")],  # type: ignore[misc]
            sni_suffixes=out.match.sni_suffixes[:32],
            dns_suffixes=out.match.dns_suffixes[:32],
            http_path_prefixes=out.match.http_path_prefixes[:16],
            ja3=out.match.ja3[:16],
            labels=labels,
            min_label_confidence=_clamp(out.match.min_label_confidence),
            min_anomaly_score=_clamp(out.match.min_anomaly_score)
            if out.match.min_anomaly_score is not None else None,
        )
        return RuleDraft(
            name=out.name.strip()[:120] or "Unnamed draft",
            rationale=out.rationale.strip()[:4000] or "No rationale supplied.",
            action=action,
            # Drafts always start alert-only; enforcement is a human decision at approval.
            mode=RuleMode.ALERT_ONLY,
            priority=min(max(int(out.priority), 0), 100000),
            match=match,
            confidence=_clamp(out.confidence),
            source=source,
            evidence_flow_ids=evidence_flow_ids[:50],
        )
    except ValueError as exc:
        raise ValidationFailure(f"model rule draft rejected by schema: {exc}") from exc


def to_alert_summary(out: schemas.LlmAlertSummary, *, source: DraftSource) -> AlertSummary:
    try:
        return AlertSummary(
            title=out.title[:200], summary=out.summary[:2000],
            severity=Severity(out.severity) if out.severity in Severity.__members__.values()
            else Severity.MEDIUM,
            recommended_actions=[a[:300] for a in out.recommended_actions[:6]],
            source=source,
        )
    except ValueError as exc:
        raise ValidationFailure(f"model alert summary rejected: {exc}") from exc


def to_narrative(out: schemas.LlmIncidentNarrative, *, source: DraftSource) -> IncidentNarrative:
    try:
        return IncidentNarrative(title=out.title[:200], narrative=out.narrative[:6000],
                                 timeline=[t[:400] for t in out.timeline[:40]], source=source)
    except ValueError as exc:
        raise ValidationFailure(f"model narrative rejected: {exc}") from exc
