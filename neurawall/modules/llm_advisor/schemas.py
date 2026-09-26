"""Model-facing structured output schemas.

Deliberately loose (plain types, every field required) so they are valid structured-
output schemas; strict bounds are enforced afterwards by :mod:`guardrails` against
the core models.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class LlmRuleMatch(BaseModel):
    src_cidrs: list[str]
    dst_cidrs: list[str]
    dst_ports: list[int]
    protocols: list[str]
    sni_suffixes: list[str]
    dns_suffixes: list[str]
    http_path_prefixes: list[str]
    ja3: list[str]
    labels: list[str]
    min_label_confidence: float
    min_anomaly_score: float | None


class LlmRuleDraft(BaseModel):
    threat_assessment: str
    name: str
    rationale: str
    action: Literal["alert", "rate_limit", "drop", "quarantine"]
    priority: int
    match: LlmRuleMatch
    confidence: float


class LlmAlertSummary(BaseModel):
    title: str
    summary: str
    severity: Literal["low", "medium", "high", "critical"]
    recommended_actions: list[str]


class LlmIncidentNarrative(BaseModel):
    title: str
    narrative: str
    timeline: list[str]


class LlmExplanation(BaseModel):
    explanation: str
