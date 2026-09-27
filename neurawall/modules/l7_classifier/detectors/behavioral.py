"""Behavioural detectors: C2 beaconing, data exfiltration, TLS fingerprint mismatch."""

from __future__ import annotations

import statistics

from neurawall.core.models import FlowRecord, ThreatLabel
from neurawall.modules.l7_classifier.detectors.base import Finding, calibrated

# JA3 hashes of mainstream browsers (extendable via the model bundle).
BROWSER_JA3 = {
    "chrome": {
        "cd08e31494f9531f560d64c695473da9",
        "b32309a26951912be7dba376398abc3b",
        "773906b0efdefa24a7f2b8eb6985bf37",
    },
    "firefox": {"579ccef312d18482fc42e2b822ca2430", "b20b44b18b853ef29ab773e921b03422"},
    "safari": {"773906b0efdefa24a7f2b8eb6985bf37"},
    "edge": {"cd08e31494f9531f560d64c695473da9"},
}
KNOWN_TOOL_JA3 = {
    "3b5074b1b5d032e5620f69f9f700ff0e": "python-requests",
    "e7d705a3286e19ea42f587b344ee6865": "tor",
    "6734f37431670b3ab4292b8f60f29984": "trickbot",
    "72a589da586844d7f0818ce684948eea": "metasploit",
    "a0e9f5d64349fb13191bc781f81f42e1": "cobalt-strike",
}
_RISKY_TLDS = frozenset({"top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "work", "su", "pw"})


def detect_beacon(flow: FlowRecord) -> list[Finding]:
    iat = flow.inter_arrival_ms
    if len(iat) < 6:
        return []
    mean = statistics.fmean(iat)
    if mean < 1000:  # sub-second periodicity is normal for streaming / polling UIs
        return []
    cv = statistics.pstdev(iat) / mean
    ev: list[tuple[str, float, str | float | None]] = []
    if cv < 0.15:
        ev.append(("low_jitter_periodicity", (0.15 - cv) * 30, round(cv, 4)))
    ev.append(("sample_count", min(len(iat) / 12, 1.5), float(len(iat))))
    total = flow.bytes_out + flow.bytes_in
    if total < 4000:
        ev.append(("small_payloads", 1.0, float(total)))
    if flow.l7 and flow.l7.tls and flow.l7.tls.ja3 in KNOWN_TOOL_JA3:
        ev.append(("tool_tls_fingerprint", 1.5, KNOWN_TOOL_JA3[flow.l7.tls.ja3]))
    if cv >= 0.15:
        return []
    conf = calibrated([w for _, w, _ in ev], -3.5)
    return [Finding(ThreatLabel.C2_BEACON, round(conf, 4), "beacon", ev)] if conf >= 0.3 else []


def detect_exfiltration(flow: FlowRecord) -> list[Finding]:
    if flow.bytes_out < 20_000_000:
        return []
    total = flow.bytes_out + flow.bytes_in
    ratio = flow.bytes_out / total
    ev: list[tuple[str, float, str | float | None]] = [
        (
            "outbound_volume_mb",
            min(flow.bytes_out / 50_000_000, 3.0),
            round(flow.bytes_out / 1e6, 1),
        ),
    ]
    if ratio > 0.9:
        ev.append(("upload_asymmetry", (ratio - 0.9) * 20, round(ratio, 4)))
    sni = flow.sni
    if sni and sni.rsplit(".", 1)[-1] in _RISKY_TLDS:
        ev.append(("risky_destination_tld", 1.5, sni))
    if flow.direction.value != "outbound":
        return []
    conf = calibrated([w for _, w, _ in ev], -3.0)
    return (
        [Finding(ThreatLabel.EXFILTRATION, round(conf, 4), "exfiltration", ev)]
        if conf >= 0.3
        else []
    )


def detect_tls_mismatch(flow: FlowRecord) -> list[Finding]:
    tls = flow.l7.tls if flow.l7 else None
    if tls is None or not tls.ja3 or not tls.claimed_client:
        return []
    claimed = tls.claimed_client.lower()
    expected = BROWSER_JA3.get(claimed)
    if expected is None or tls.ja3 in expected:
        return []
    ev: list[tuple[str, float, str | float | None]] = [("claimed_client", 2.0, claimed)]
    tool = KNOWN_TOOL_JA3.get(tls.ja3)
    if tool:
        ev.append(("known_tool_ja3", 3.0, tool))
    else:
        ev.append(("unknown_ja3", 0.5, tls.ja3))
    conf = calibrated([w for _, w, _ in ev], -2.5)
    return [Finding(ThreatLabel.TLS_MISMATCH, round(conf, 4), "tls_fingerprint", ev)]
