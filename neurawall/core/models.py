"""Canonical, immutable, versioned data types (blueprint §4.1, §8).

Every inter-module payload is one of these types. They are frozen, reject unknown
fields, and bound every string/list so that untrusted input cannot grow unbounded.
"""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from neurawall.core.validation import (
    CIDR,
    DomainName,
    DomainSuffix,
    IPAddress,
    Port,
    Probability,
    SafeText,
)

SCHEMA_VERSION = "1.0"


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_max_length=4096)


def new_id() -> str:
    return uuid.uuid4().hex


def now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Flow records
# ---------------------------------------------------------------------------


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"


class HttpMeta(Frozen):
    method: Annotated[str, Field(max_length=16)] = "GET"
    host: Annotated[str, Field(max_length=253)] | None = None
    path: Annotated[SafeText, Field(max_length=2048)] = "/"
    user_agent: Annotated[SafeText, Field(max_length=512)] | None = None
    content_type: Annotated[str, Field(max_length=128)] | None = None
    body_len: Annotated[int, Field(ge=0)] = 0
    status: Annotated[int, Field(ge=0, le=999)] | None = None


class DnsMeta(Frozen):
    qname: DomainName
    qtype: Annotated[str, Field(max_length=10)] = "A"
    rcode: Annotated[str, Field(max_length=16)] = "NOERROR"
    answers: Annotated[int, Field(ge=0, le=1024)] = 0


class TlsMeta(Frozen):
    sni: DomainName | None = None
    version: Annotated[str, Field(max_length=16)] | None = None
    ja3: Annotated[str, Field(max_length=64)] | None = None
    ja4: Annotated[str, Field(max_length=64)] | None = None
    alpn: Annotated[list[Annotated[str, Field(max_length=32)]], Field(max_length=8)] = []
    #: Client family claimed by the HTTP User-Agent (e.g. "chrome"); compared with JA3.
    claimed_client: Annotated[str, Field(max_length=32)] | None = None


class L7Meta(Frozen):
    http: HttpMeta | None = None
    dns: DnsMeta | None = None
    tls: TlsMeta | None = None


class FlowRecord(Frozen):
    """One assembled flow, produced by the flow collector. Metadata only — no payloads."""

    schema_version: str = SCHEMA_VERSION
    flow_id: Annotated[str, Field(min_length=1, max_length=64)] = Field(default_factory=new_id)
    node_id: Annotated[str, Field(min_length=1, max_length=64)] = "local"
    ts_start: float = Field(default_factory=now)
    ts_end: float | None = None
    src_ip: IPAddress
    dst_ip: IPAddress
    src_port: Port = 0
    dst_port: Port = 0
    protocol: Protocol = Protocol.TCP
    direction: Direction = Direction.OUTBOUND
    bytes_out: Annotated[int, Field(ge=0)] = 0
    bytes_in: Annotated[int, Field(ge=0)] = 0
    packets_out: Annotated[int, Field(ge=0)] = 0
    packets_in: Annotated[int, Field(ge=0)] = 0
    tcp_flags: Annotated[str, Field(max_length=64)] = ""
    #: Inter-arrival times (ms) of the most recent connections between this pair; beacon input.
    inter_arrival_ms: Annotated[list[Annotated[float, Field(ge=0)]], Field(max_length=256)] = []
    l7: L7Meta | None = None

    @model_validator(mode="after")
    def _check_times(self) -> FlowRecord:
        if self.ts_end is not None and self.ts_end < self.ts_start:
            raise ValueError("ts_end precedes ts_start")
        return self

    @property
    def duration(self) -> float:
        return max(0.0, (self.ts_end or self.ts_start) - self.ts_start)

    @property
    def sni(self) -> str | None:
        return self.l7.tls.sni if self.l7 and self.l7.tls else None

    @property
    def dns_qname(self) -> str | None:
        return self.l7.dns.qname if self.l7 and self.l7.dns else None


# ---------------------------------------------------------------------------
# Tier outputs
# ---------------------------------------------------------------------------


class Attribution(Frozen):
    feature: Annotated[str, Field(max_length=64)]
    contribution: float
    value: float | str | None = None


class AnomalyScore(Frozen):
    flow_id: str
    score: Probability
    confidence: Probability
    top_features: Annotated[list[Attribution], Field(max_length=8)] = []
    model_version: str = "tier1"


class ThreatLabel(StrEnum):
    BENIGN = "benign"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    DGA = "dga"
    DNS_TUNNEL = "dns_tunnel"
    C2_BEACON = "c2_beacon"
    EXFILTRATION = "exfiltration"
    TLS_MISMATCH = "tls_fingerprint_mismatch"
    NOVEL = "novel"


class Classification(Frozen):
    flow_id: str
    label: ThreatLabel
    confidence: Probability
    detector: Annotated[str, Field(max_length=64)]
    attributions: Annotated[list[Attribution], Field(max_length=8)] = []
    model_version: str = "tier2"


class Evidence(Frozen):
    """A flow plus every signal the tiers produced for it."""

    flow: FlowRecord
    anomaly: AnomalyScore | None = None
    classifications: tuple[Classification, ...] = ()

    @property
    def malicious_labels(self) -> list[Classification]:
        return [c for c in self.classifications if c.label != ThreatLabel.BENIGN]


# ---------------------------------------------------------------------------
# Rules, verdicts, bundles
# ---------------------------------------------------------------------------


class Action(StrEnum):
    ALLOW = "allow"
    ALERT = "alert"
    RATE_LIMIT = "rate_limit"
    DROP = "drop"
    QUARANTINE = "quarantine"

    @property
    def severity(self) -> int:
        return _ACTION_SEVERITY[self]

    @property
    def is_blocking(self) -> bool:
        return self in (Action.DROP, Action.QUARANTINE, Action.RATE_LIMIT)


_ACTION_SEVERITY = {
    Action.ALLOW: 0,
    Action.ALERT: 1,
    Action.RATE_LIMIT: 2,
    Action.DROP: 3,
    Action.QUARANTINE: 4,
}


class RuleMode(StrEnum):
    ENFORCE = "enforce"
    ALERT_ONLY = "alert_only"


class RuleMatch(Frozen):
    """Match criteria. All populated criteria must hold (logical AND); empty = wildcard.

    A match with no criteria at all is rejected — a rule must say what it matches.
    """

    src_cidrs: Annotated[list[CIDR], Field(max_length=256)] = []
    dst_cidrs: Annotated[list[CIDR], Field(max_length=256)] = []
    dst_ports: Annotated[list[Port], Field(max_length=64)] = []
    protocols: Annotated[list[Protocol], Field(max_length=3)] = []
    directions: Annotated[list[Direction], Field(max_length=3)] = []
    sni_suffixes: Annotated[list[DomainSuffix], Field(max_length=128)] = []
    dns_suffixes: Annotated[list[DomainSuffix], Field(max_length=128)] = []
    http_path_prefixes: Annotated[
        list[Annotated[str, Field(max_length=256)]], Field(max_length=64)
    ] = []
    ja3: Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=64)] = []
    labels: Annotated[list[ThreatLabel], Field(max_length=16)] = []
    min_label_confidence: Probability = 0.0
    min_anomaly_score: Probability | None = None

    @model_validator(mode="after")
    def _non_empty(self) -> RuleMatch:
        populated = [
            self.src_cidrs,
            self.dst_cidrs,
            self.dst_ports,
            self.protocols,
            self.directions,
            self.sni_suffixes,
            self.dns_suffixes,
            self.http_path_prefixes,
            self.ja3,
            self.labels,
        ]
        if not any(populated) and self.min_anomaly_score is None:
            raise ValueError("rule match must specify at least one criterion")
        return self


class Rule(Frozen):
    """An approved, enforceable rule. Only the policy engine turns these into actions."""

    id: Annotated[str, Field(pattern=r"^R-[0-9]{6}$")]
    name: Annotated[SafeText, Field(min_length=1, max_length=120)]
    description: Annotated[SafeText, Field(max_length=2000)] = ""
    #: Mandatory: 100% of active rules carry a rationale record (blueprint §1.4).
    rationale: Annotated[SafeText, Field(min_length=1, max_length=4000)]
    priority: Annotated[int, Field(ge=0, le=100000)] = 1000
    action: Action
    mode: RuleMode = RuleMode.ENFORCE
    match: RuleMatch
    enabled: bool = True
    version: Annotated[int, Field(ge=1)] = 1
    created_by: Annotated[str, Field(max_length=120)] = "system"
    approved_by: Annotated[str, Field(max_length=120)] | None = None
    created_at: float = Field(default_factory=now)


class SimulationResult(Frozen):
    flows_evaluated: int
    flows_matched: int
    #: Fraction of *legitimate* evaluated traffic the rule would affect (blueprint §17).
    blast_radius: Probability
    legitimate_matched: int = 0
    would_block: int
    affected_sources: int
    affected_destinations: int
    sample_matches: Annotated[list[str], Field(max_length=20)] = []
    exceeds_threshold: bool = False
    threshold: Probability = 0.01


class DraftSource(StrEnum):
    LLM = "llm"
    HEURISTIC = "heuristic"
    OPERATOR = "operator"


class RuleDraft(Frozen):
    """A *proposed* rule. Never enforceable; requires human approval to become a Rule."""

    draft_id: str = Field(default_factory=new_id)
    name: Annotated[SafeText, Field(min_length=1, max_length=120)]
    rationale: Annotated[SafeText, Field(min_length=1, max_length=4000)]
    action: Action
    mode: RuleMode = RuleMode.ALERT_ONLY
    priority: Annotated[int, Field(ge=0, le=100000)] = 500
    match: RuleMatch
    confidence: Probability
    source: DraftSource
    evidence_flow_ids: Annotated[list[str], Field(max_length=50)] = []
    simulation: SimulationResult | None = None


class Verdict(Frozen):
    flow_id: str
    action: Action
    #: Every enforced drop maps to an explicit rule ID (blueprint §1.3).
    rule_id: str | None = None
    enforced: bool
    reasons: Annotated[list[Annotated[str, Field(max_length=300)]], Field(max_length=16)] = []
    anomaly_score: Probability | None = None
    labels: list[ThreatLabel] = []
    ts: float = Field(default_factory=now)

    @model_validator(mode="after")
    def _blocking_requires_rule(self) -> Verdict:
        if self.enforced and self.action.is_blocking and not self.rule_id:
            raise ValueError("an enforced blocking verdict must reference a rule id")
        return self


class PolicyBundle(Frozen):
    bundle_id: str = Field(default_factory=new_id)
    version: Annotated[int, Field(ge=1)]
    created_at: float = Field(default_factory=now)
    default_action: Literal[Action.ALLOW, Action.ALERT] = Action.ALLOW
    rules: Annotated[list[Rule], Field(max_length=10000)]
    anomaly_alert_threshold: Probability = 0.8
    #: Without a matching rule, a malicious label at/above this confidence raises an alert.
    classifier_alert_threshold: Probability = 0.7


class SignedEnvelope(Frozen):
    """Detached Ed25519 signature over the canonical JSON of ``payload``."""

    payload: dict[str, object]
    signature: str  # base64
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"


# ---------------------------------------------------------------------------
# Tier 3 outputs
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSummary(Frozen):
    title: Annotated[SafeText, Field(max_length=200)]
    summary: Annotated[SafeText, Field(max_length=2000)]
    severity: Severity
    recommended_actions: Annotated[
        list[Annotated[SafeText, Field(max_length=300)]], Field(max_length=6)
    ] = []
    source: DraftSource


class IncidentNarrative(Frozen):
    title: Annotated[SafeText, Field(max_length=200)]
    narrative: Annotated[SafeText, Field(max_length=6000)]
    timeline: Annotated[list[Annotated[SafeText, Field(max_length=400)]], Field(max_length=40)] = []
    source: DraftSource


class HygieneFinding(Frozen):
    rule_id: str
    kind: Literal["shadowed", "redundant", "overly_broad", "stale", "conflict"]
    detail: Annotated[SafeText, Field(max_length=600)]
    related_rule_id: str | None = None
