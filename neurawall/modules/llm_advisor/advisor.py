"""Tier 3 — LLM advisor facade (blueprint §5.3).

Produces :class:`RuleDraft` (never :class:`Rule`), alert summaries, incident narratives
and verdict explanations. Budgeted per hour; degrades to the deterministic heuristic
advisor when Claude is not configured, over budget or unavailable.
"""

from __future__ import annotations

from typing import Protocol, TypeVar

from pydantic import BaseModel

from neurawall.core.errors import RecoverableError, ValidationFailure
from neurawall.core.logging import get_logger
from neurawall.core.models import (
    AlertSummary,
    DraftSource,
    Evidence,
    IncidentNarrative,
    Rule,
    RuleDraft,
    Verdict,
)
from neurawall.core.telemetry import REGISTRY
from neurawall.modules.llm_advisor import guardrails, heuristic, schemas
from neurawall.modules.llm_advisor.context import flow_context, rules_context, verdict_context
from neurawall.security.ratelimit import HourlyBudget

log = get_logger(__name__)
T = TypeVar("T", bound=BaseModel)

_calls = REGISTRY.counter("neurawall_tier3_calls_total", "Tier 3 calls by source and outcome")
MAX_EVIDENCE = 40


class Backend(Protocol):
    def generate(self, task: str, context: str, output: type[T]) -> T: ...


class LlmAdvisor:
    def __init__(self, backend: Backend | None, *, max_calls_per_hour: int = 120) -> None:
        self.backend = backend
        self.budget = HourlyBudget(max_calls_per_hour)
        self.last_error: str | None = None

    @property
    def mode(self) -> str:
        if self.backend is None:
            return "offline"
        return "degraded" if self.last_error else "online"

    # -- public API -----------------------------------------------------------

    def draft_rule(self, evidence: list[Evidence], rules: list[Rule]) -> RuleDraft:
        evidence = evidence[:MAX_EVIDENCE]
        ids = [e.flow.flow_id for e in evidence]
        out, source = self._run(
            "Draft one firewall rule that addresses the threat shown by these flows.",
            {"flows": [flow_context(e) for e in evidence], "existing_rules": rules_context(rules)},
            schemas.LlmRuleDraft, lambda: heuristic.draft_rule(evidence, rules))
        try:
            return guardrails.to_rule_draft(out, source=source, evidence_flow_ids=ids)
        except ValidationFailure as exc:
            log.warning("tier3 draft rejected by guardrails; using heuristic", error=str(exc))
            _calls.inc(source=source.value, outcome="rejected")
            return guardrails.to_rule_draft(heuristic.draft_rule(evidence, rules),
                                            source=DraftSource.HEURISTIC, evidence_flow_ids=ids)

    def summarize_alert(self, evidence: list[Evidence]) -> AlertSummary:
        evidence = evidence[:MAX_EVIDENCE]
        out, source = self._run(
            "Triage this alert: give a concise title, a one-paragraph summary for an analyst, "
            "a severity, and up to four recommended actions.",
            {"flows": [flow_context(e) for e in evidence]},
            schemas.LlmAlertSummary, lambda: heuristic.summarize(evidence))
        return guardrails.to_alert_summary(out, source=source)

    def narrate_incident(self, evidence: list[Evidence]) -> IncidentNarrative:
        evidence = sorted(evidence, key=lambda e: e.flow.ts_start)[:MAX_EVIDENCE]
        out, source = self._run(
            "Reconstruct the incident: a title, a prose narrative of what likely happened and "
            "in what order, and a timeline of the key events (one line each, UTC timestamps).",
            {"flows": [flow_context(e) for e in evidence]},
            schemas.LlmIncidentNarrative, lambda: heuristic.narrate(evidence))
        return guardrails.to_narrative(out, source=source)

    def explain_verdict(self, verdict: Verdict, rule: Rule | None,
                        evidence: Evidence | None) -> tuple[str, DraftSource]:
        payload: dict[str, object] = {"verdict": verdict_context(verdict)}
        if rule:
            payload["rule"] = rules_context([rule])[0] | {"rationale": rule.rationale}
        if evidence:
            payload["flow"] = flow_context(evidence)
        out, source = self._run(
            "Explain in plain language, for a non-specialist, why this flow received this "
            "verdict. Three to five sentences.",
            payload, schemas.LlmExplanation, lambda: heuristic.explain(verdict, rule, evidence))
        return out.explanation[:3000], source

    # -- internals ---------------------------------------------------------------

    def _run(self, task: str, payload: dict[str, object], output: type[T],
             fallback: object) -> tuple[T, DraftSource]:
        if self.backend is not None and self.budget.try_spend():
            markers = guardrails.injection_markers(payload)
            context = guardrails.wrap_untrusted(payload | {"injection_markers": markers})
            try:
                result = self.backend.generate(task, context, output)
                self.last_error = None
                _calls.inc(source="llm", outcome="ok")
                return result, DraftSource.LLM
            except RecoverableError as exc:
                self.last_error = exc.message
                _calls.inc(source="llm", outcome="error")
                log.warning("tier3 degraded to heuristic advisor", error=exc.message)
        elif self.backend is not None:
            _calls.inc(source="llm", outcome="budget_exhausted")
        _calls.inc(source="heuristic", outcome="ok")
        return fallback(), DraftSource.HEURISTIC  # type: ignore[operator]
