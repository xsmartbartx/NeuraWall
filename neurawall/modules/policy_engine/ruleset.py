"""Rule representation, matching, ordering and deterministic hygiene analysis."""

from __future__ import annotations

import ipaddress

from neurawall.core.models import (
    Evidence,
    HygieneFinding,
    Rule,
    RuleMatch,
)
from neurawall.core.validation import domain_matches_suffix, ip_in_any


def match_flow(match: RuleMatch, ev: Evidence) -> bool:
    f = ev.flow
    if match.protocols and f.protocol not in match.protocols:
        return False
    if match.directions and f.direction not in match.directions:
        return False
    if match.dst_ports and f.dst_port not in match.dst_ports:
        return False
    if match.src_cidrs and not ip_in_any(f.src_ip, match.src_cidrs):
        return False
    if match.dst_cidrs and not ip_in_any(f.dst_ip, match.dst_cidrs):
        return False
    if match.sni_suffixes and not domain_matches_suffix(f.sni, match.sni_suffixes):
        return False
    if match.dns_suffixes and not domain_matches_suffix(f.dns_qname, match.dns_suffixes):
        return False
    if match.http_path_prefixes:
        path = f.l7.http.path if f.l7 and f.l7.http else None
        if path is None or not any(path.startswith(p) for p in match.http_path_prefixes):
            return False
    if match.ja3:
        ja3 = f.l7.tls.ja3 if f.l7 and f.l7.tls else None
        if ja3 not in match.ja3:
            return False
    if match.labels and not any(
        c.label in match.labels and c.confidence >= match.min_label_confidence
        for c in ev.classifications
    ):
        return False
    return not (
        match.min_anomaly_score is not None
        and (ev.anomaly is None or ev.anomaly.score < match.min_anomaly_score)
    )


def order_rules(rules: list[Rule]) -> list[Rule]:
    """Evaluation order: ascending priority number, then rule id (deterministic)."""
    return sorted((r for r in rules if r.enabled), key=lambda r: (r.priority, r.id))


# ---------------------------------------------------------------------------
# Hygiene: shadowed / redundant / overly broad rules
# ---------------------------------------------------------------------------


def _cidrs_cover(outer: list[str], inner: list[str]) -> bool:
    if not outer:
        return True
    if not inner:
        return False
    nets_o = [ipaddress.ip_network(c, strict=False) for c in outer]
    for c in inner:
        n = ipaddress.ip_network(c, strict=False)
        if not any(o.version == n.version and n.subnet_of(o) for o in nets_o):  # type: ignore[arg-type]
            return False
    return True


def _set_covers(outer: list[object], inner: list[object]) -> bool:
    return not outer or (bool(inner) and set(inner) <= set(outer))


def _suffix_covers(outer: list[str], inner: list[str]) -> bool:
    return not outer or (bool(inner) and all(domain_matches_suffix(i, outer) for i in inner))


def match_covers(outer: RuleMatch, inner: RuleMatch) -> bool:
    """True if every flow matched by ``inner`` is also matched by ``outer`` (conservative)."""
    return (
        _cidrs_cover(outer.src_cidrs, inner.src_cidrs)
        and _cidrs_cover(outer.dst_cidrs, inner.dst_cidrs)
        and _set_covers(list(outer.dst_ports), list(inner.dst_ports))
        and _set_covers(list(outer.protocols), list(inner.protocols))
        and _set_covers(list(outer.directions), list(inner.directions))
        and _suffix_covers(outer.sni_suffixes, inner.sni_suffixes)
        and _suffix_covers(outer.dns_suffixes, inner.dns_suffixes)
        and (not outer.http_path_prefixes or (bool(inner.http_path_prefixes) and all(
            any(i.startswith(o) for o in outer.http_path_prefixes) for i in inner.http_path_prefixes)))
        and _set_covers(list(outer.ja3), list(inner.ja3))
        and _set_covers(list(outer.labels), list(inner.labels))
        and outer.min_label_confidence <= inner.min_label_confidence
        and (outer.min_anomaly_score is None or (
            inner.min_anomaly_score is not None and outer.min_anomaly_score <= inner.min_anomaly_score))
    )


def _is_overly_broad(m: RuleMatch) -> bool:
    wide_src = not m.src_cidrs or any(c.endswith("/0") for c in m.src_cidrs)
    wide_dst = not m.dst_cidrs or any(c.endswith("/0") for c in m.dst_cidrs)
    no_l7 = not (m.sni_suffixes or m.dns_suffixes or m.http_path_prefixes or m.ja3 or m.labels)
    return wide_src and wide_dst and no_l7 and m.min_anomaly_score is None and \
        (not m.dst_ports or len(m.dst_ports) > 20)


def analyze_hygiene(rules: list[Rule]) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    ordered = order_rules(rules)
    for i, later in enumerate(ordered):
        for earlier in ordered[:i]:
            if match_covers(earlier.match, later.match):
                kind = "redundant" if earlier.action == later.action else "shadowed"
                findings.append(HygieneFinding(
                    rule_id=later.id, kind=kind, related_rule_id=earlier.id,
                    detail=(f"{later.id} can never match: {earlier.id} (priority {earlier.priority})"
                            f" covers all its traffic"
                            + (" with the same action." if kind == "redundant"
                               else f" and applies '{earlier.action}' instead of '{later.action}'.")),
                ))
                break
        if later.action.is_blocking and _is_overly_broad(later.match):
            findings.append(HygieneFinding(
                rule_id=later.id, kind="overly_broad",
                detail=f"{later.id} blocks with no source, destination or L7 restriction.",
            ))
    return findings
