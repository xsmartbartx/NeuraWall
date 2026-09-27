"""Enforcement backends (blueprint §4.2 ``datapath``).

The datapath never calls inference. It applies two things it is handed by the policy
engine: the compiled *static* rule set from a signed bundle, and *dynamic* per-flow /
per-host verdicts (the analogue of the eBPF verdict map), each with a TTL.

Backends:

* :class:`DryRunBackend` — computes and records everything, touches nothing. Default.
* :class:`NftablesBackend` — materialises the rule set into an ``inet neurawall`` table
  via ``nft -f -`` (Linux, CAP_NET_ADMIN). L3/L4 rules compile to static nft rules;
  L7/label/score rules are enforced through timed sets populated from verdicts.

An eBPF/XDP backend implements the same protocol (roadmap; see ADR-0002).
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Protocol

from neurawall.core.errors import RecoverableError
from neurawall.core.logging import get_logger
from neurawall.core.models import Action, FlowRecord, PolicyBundle, Rule, RuleMode, Verdict
from neurawall.core.telemetry import REGISTRY

log = get_logger(__name__)
_applied = REGISTRY.counter("neurawall_datapath_bundle_applies_total", "Bundle applies by result")
_dynamic = REGISTRY.counter("neurawall_datapath_dynamic_verdicts_total", "Dynamic verdicts pushed")

DYNAMIC_TTL_SECONDS = 600


@dataclass
class ApplyResult:
    ok: bool
    version: int
    static_rules: int
    dynamic_rules: int
    detail: str = ""


@dataclass
class DatapathState:
    backend: str
    applied_version: int = 0
    applied_at: float = 0.0
    static_rules: int = 0
    dynamic_rules: int = 0
    active_blocks: int = 0
    last_error: str | None = None
    fail_mode: str = "open"
    extra: dict[str, object] = field(default_factory=dict)


class EnforcementBackend(Protocol):
    name: str

    def apply_bundle(self, bundle: PolicyBundle) -> ApplyResult: ...

    def apply_verdict(self, flow: FlowRecord, verdict: Verdict) -> bool: ...

    def state(self) -> DatapathState: ...


def is_static(rule: Rule) -> bool:
    """A rule the kernel can evaluate on its own (pure L3/L4 match).

    Direction constraints need knowledge of the site's local networks, which the
    kernel ruleset does not have, so they are enforced dynamically (never over-block).
    """
    m = rule.match
    return not (m.sni_suffixes or m.dns_suffixes or m.http_path_prefixes or m.ja3 or m.labels
                or m.directions or m.min_anomaly_score is not None)


def enforceable(rule: Rule) -> bool:
    return rule.enabled and rule.mode == RuleMode.ENFORCE and rule.action.is_blocking


class VerdictCache:
    """Bounded TTL map of flow key -> action; the userspace mirror of the verdict map."""

    def __init__(self, max_entries: int = 100_000, ttl: float = DYNAMIC_TTL_SECONDS) -> None:
        self.max_entries = max_entries
        self.ttl = ttl
        self._d: OrderedDict[tuple[str, str, int, str], tuple[Action, float, str]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def key(f: FlowRecord) -> tuple[str, str, int, str]:
        return (f.src_ip, f.dst_ip, f.dst_port, f.protocol.value)

    def put(self, f: FlowRecord, action: Action, rule_id: str) -> None:
        with self._lock:
            self._d[self.key(f)] = (action, time.time() + self.ttl, rule_id)
            self._d.move_to_end(self.key(f))
            while len(self._d) > self.max_entries:
                self._d.popitem(last=False)

    def get(self, f: FlowRecord) -> tuple[Action, str] | None:
        with self._lock:
            hit = self._d.get(self.key(f))
            if hit is None:
                return None
            if hit[1] < time.time():
                del self._d[self.key(f)]
                return None
            return hit[0], hit[2]

    def __len__(self) -> int:
        now = time.time()
        return sum(1 for v in self._d.values() if v[1] >= now)


# ---------------------------------------------------------------------------
# nftables compilation
# ---------------------------------------------------------------------------


def _family_split(cidrs: list[str]) -> tuple[list[str], list[str]]:
    v4 = [c for c in cidrs if ipaddress.ip_network(c, strict=False).version == 4]
    v6 = [c for c in cidrs if ipaddress.ip_network(c, strict=False).version == 6]
    return v4, v6


def _verdict_stmt(rule: Rule) -> str:
    comment = f'comment "{rule.id}"'
    if rule.action == Action.RATE_LIMIT:
        return f"limit rate over 50/second burst 100 packets drop {comment}"
    return f"counter drop {comment}"


def compile_rule(rule: Rule) -> list[str]:
    """One or more nft rule lines for a static rule (split per address family)."""
    m = rule.match
    lines: list[str] = []
    src4, src6 = _family_split(m.src_cidrs)
    dst4, dst6 = _family_split(m.dst_cidrs)
    families = []
    if (src4 or dst4) and not (src6 or dst6):
        families = [("ip", src4, dst4)]
    elif (src6 or dst6) and not (src4 or dst4):
        families = [("ip6", src6, dst6)]
    elif src4 or dst4 or src6 or dst6:
        families = [("ip", src4, dst4), ("ip6", src6, dst6)]
    else:
        families = [(None, [], [])]
    protos = [p.value for p in m.protocols] or (["tcp", "udp"] if m.dst_ports else [])
    for fam, src, dst in families:
        if fam and (m.src_cidrs and not src or m.dst_cidrs and not dst):
            continue  # this family has no addresses for a populated criterion
        for proto in protos or [None]:
            parts: list[str] = []
            if fam and src:
                parts.append(f"{fam} saddr {{ {', '.join(src)} }}")
            if fam and dst:
                parts.append(f"{fam} daddr {{ {', '.join(dst)} }}")
            if proto == "icmp":
                parts.append("meta l4proto { icmp, ipv6-icmp }")
            elif proto:
                parts.append(f"meta l4proto {proto}")
                if m.dst_ports:
                    parts.append(f"{proto} dport {{ {', '.join(str(p) for p in m.dst_ports)} }}")
            parts.append(_verdict_stmt(rule))
            lines.append(" ".join(parts))
    return lines


def render_ruleset(bundle: PolicyBundle) -> str:
    rules = sorted((r for r in bundle.rules if enforceable(r) and is_static(r)),
                   key=lambda r: (r.priority, r.id))
    # ALLOW rules with higher priority than blocking rules act as exceptions.
    allows = [r for r in bundle.rules if r.enabled and r.action == Action.ALLOW and is_static(r)]
    body: list[str] = []
    for r in sorted([*rules, *allows], key=lambda r: (r.priority, r.id)):
        for line in compile_rule(r):
            if r.action == Action.ALLOW:
                line = line.replace("counter drop", "accept")
            body.append(f"    {line}")
    ttl = f"{DYNAMIC_TTL_SECONDS}s"
    return "\n".join([
        "table inet neurawall",
        "delete table inet neurawall",
        "table inet neurawall {",
        f"  set dyn_drop4 {{ type ipv4_addr . ipv4_addr . inet_service; flags timeout; timeout {ttl}; }}",
        f"  set dyn_drop6 {{ type ipv6_addr . ipv6_addr . inet_service; flags timeout; timeout {ttl}; }}",
        f"  set quarantine4 {{ type ipv4_addr; flags timeout; timeout {ttl}; }}",
        f"  set quarantine6 {{ type ipv6_addr; flags timeout; timeout {ttl}; }}",
        "  chain enforce {",
        "    ip saddr . ip daddr . th dport @dyn_drop4 counter drop",
        "    ip6 saddr . ip6 daddr . th dport @dyn_drop6 counter drop",
        "    ip saddr @quarantine4 counter drop",
        "    ip6 saddr @quarantine6 counter drop",
        *body,
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter - 10; policy accept;",
        "    jump enforce",
        "  }",
        "  chain input {",
        "    type filter hook input priority filter - 10; policy accept;",
        "    iif lo accept",
        "    jump enforce",
        "  }",
        "}",
        "",
    ])


class DryRunBackend:
    """Computes enforcement without touching the host. Safe default everywhere."""

    name = "dry-run"

    def __init__(self) -> None:
        self.cache = VerdictCache()
        self.last_ruleset = ""
        self._state = DatapathState(backend=self.name)

    def apply_bundle(self, bundle: PolicyBundle) -> ApplyResult:
        self.last_ruleset = render_ruleset(bundle)
        static = sum(1 for r in bundle.rules if enforceable(r) and is_static(r))
        dynamic = sum(1 for r in bundle.rules if enforceable(r) and not is_static(r))
        self._state.applied_version = bundle.version
        self._state.applied_at = time.time()
        self._state.static_rules, self._state.dynamic_rules = static, dynamic
        _applied.inc(backend=self.name, result="ok")
        return ApplyResult(True, bundle.version, static, dynamic, "rendered (dry run)")

    def apply_verdict(self, flow: FlowRecord, verdict: Verdict) -> bool:
        if not (verdict.enforced and verdict.action.is_blocking and verdict.rule_id):
            return False
        self.cache.put(flow, verdict.action, verdict.rule_id)
        _dynamic.inc(backend=self.name, action=verdict.action.value)
        return True

    def state(self) -> DatapathState:
        self._state.active_blocks = len(self.cache)
        return self._state


class NftablesBackend(DryRunBackend):
    name = "nftables"

    def __init__(self, nft_path: str | None = None) -> None:
        super().__init__()
        self.nft = nft_path or shutil.which("nft")
        if not self.nft:
            raise RecoverableError("nft binary not found; install nftables or use the dry-run backend")
        self._state = DatapathState(backend=self.name)

    def _run(self, script: str) -> None:
        proc = subprocess.run([self.nft, "-f", "-"], input=script, text=True,  # noqa: S603
                              capture_output=True, timeout=15, check=False)
        if proc.returncode != 0:
            raise RecoverableError(f"nft failed: {proc.stderr.strip()[:500]}")

    def apply_bundle(self, bundle: PolicyBundle) -> ApplyResult:
        script = render_ruleset(bundle)
        try:
            self._run(script)  # atomic: nft applies the whole script or nothing
        except RecoverableError as exc:
            # Fail open on the *new* bundle: the previous ruleset remains in force.
            self._state.last_error = exc.message
            _applied.inc(backend=self.name, result="error")
            log.error("nftables apply failed; last-known-good ruleset retained", error=exc.message)
            return ApplyResult(False, bundle.version, 0, 0, exc.message)
        self.last_ruleset = script
        result = super().apply_bundle(bundle)
        self._state.last_error = None
        return ApplyResult(True, result.version, result.static_rules, result.dynamic_rules, "applied")

    def apply_verdict(self, flow: FlowRecord, verdict: Verdict) -> bool:
        if not super().apply_verdict(flow, verdict):
            return False
        v6 = ":" in flow.src_ip
        if verdict.action == Action.QUARANTINE:
            element = f"add element inet neurawall quarantine{6 if v6 else 4} {{ {flow.src_ip} }}"
        else:
            element = (f"add element inet neurawall dyn_drop{6 if v6 else 4} "
                       f"{{ {flow.src_ip} . {flow.dst_ip} . {flow.dst_port} }}")
        try:
            self._run(element + "\n")
            return True
        except RecoverableError as exc:
            self._state.last_error = exc.message
            return False


def make_backend(name: str) -> EnforcementBackend:
    if name == "nftables":
        return NftablesBackend()
    if name == "dry-run":
        return DryRunBackend()
    raise ValueError(f"unknown datapath backend {name!r} (expected 'dry-run' or 'nftables')")
