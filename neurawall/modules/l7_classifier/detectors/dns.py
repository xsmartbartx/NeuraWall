"""DGA and DNS tunnelling detection from query names alone."""

from __future__ import annotations

import math
import re
from collections import Counter, OrderedDict, deque

from neurawall.core.models import FlowRecord, ThreatLabel
from neurawall.modules.l7_classifier.detectors.base import Finding, calibrated

# Most frequent English letter bigrams; human-chosen domain labels are rich in them.
_COMMON_BIGRAMS = frozenset(
    [
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
        "ca",
        "el",
        "ta",
        "la",
        "ns",
        "di",
        "fo",
        "ho",
        "pe",
        "ec",
        "pr",
        "no",
        "ct",
        "us",
        "ac",
        "ot",
        "il",
        "tr",
        "ly",
        "nc",
        "et",
        "ut",
        "ss",
        "so",
        "rs",
        "un",
        "lo",
        "wa",
        "ge",
        "ie",
        "wh",
        "ee",
        "wi",
        "em",
        "ad",
        "ol",
        "rt",
        "po",
        "we",
        "na",
        "ul",
        "ni",
        "ts",
        "mo",
        "ow",
        "pa",
        "im",
        "mi",
        "ai",
        "sh",
        "ir",
        "su",
        "id",
        "os",
        "iv",
        "ia",
        "am",
        "fi",
        "ci",
        "vi",
        "pl",
        "ig",
        "tu",
        "ev",
        "ld",
        "ry",
        "mp",
        "fe",
        "bl",
        "ab",
        "gh",
        "ty",
        "op",
        "wo",
        "sa",
        "ay",
        "ex",
        "ke",
        "fr",
        "oo",
        "av",
        "ag",
        "if",
        "ap",
        "gr",
        "od",
        "bo",
        "sp",
        "rd",
        "do",
        "uc",
        "bu",
        "ei",
        "ov",
        "by",
        "rm",
        "ep",
        "tt",
        "oc",
        "fa",
        "ef",
        "cu",
        "rn",
        "sc",
        "gi",
        "da",
        "yo",
        "cr",
        "cl",
        "du",
        "ga",
        "qu",
        "ue",
        "ff",
        "ba",
        "ey",
        "ls",
        "va",
        "um",
        "pp",
        "ua",
        "up",
        "lu",
        "go",
        "ht",
        "ru",
        "ug",
        "ds",
        "lt",
        "pi",
        "rc",
        "rr",
        "eg",
        "au",
        "ck",
        "ew",
        "mu",
        "br",
        "bi",
        "pt",
        "ak",
        "pu",
        "ui",
        "rg",
        "ib",
        "tl",
        "ny",
        "ki",
        "rk",
        "ys",
        "ob",
        "mm",
        "fu",
        "ph",
        "og",
        "ms",
        "ye",
        "ud",
        "mb",
        "ip",
        "ub",
        "oi",
        "rl",
        "gu",
        "dr",
        "hr",
        "cc",
        "tw",
        "ft",
        "wn",
        "nu",
        "af",
        "hu",
        "nn",
        "eo",
        "vo",
        "rv",
        "nf",
        "xp",
        "gn",
        "sm",
        "fl",
        "iz",
        "ok",
        "nl",
        "my",
        "gl",
        "aw",
        "sy",
        "oa",
    ]
)
_HEX_OR_B32 = re.compile(r"^[a-f0-9]{16,}$|^[a-z2-7]{24,}$")
_SUSPICIOUS_TLDS = frozenset(
    {"top", "xyz", "info", "tk", "ml", "ga", "cf", "gq", "biz", "click", "work", "io", "su", "pw"}
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


_CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxz]{4,}")


def _bigram_score(label: str) -> float:
    """Share of letter bigrams (within alphabetic runs only) that are common in English."""
    bigrams = [run[i : i + 2] for run in re.findall(r"[a-z]+", label) for i in range(len(run) - 1)]
    if len(bigrams) < 4:
        return 1.0 if len(label) < 8 else 0.3
    return sum(b in _COMMON_BIGRAMS for b in bigrams) / len(bigrams)


class NxdomainWindow:
    """Per-source NXDOMAIN count over a sliding window; DGA malware fails many lookups."""

    def __init__(self, window_seconds: float = 60.0, max_sources: int = 50000) -> None:
        self.window = window_seconds
        self.max_sources = max_sources
        self._events: OrderedDict[str, deque[float]] = OrderedDict()

    def observe(self, src: str, ts: float) -> int:
        q = self._events.get(src)
        if q is None:
            q = deque(maxlen=1024)
            self._events[src] = q
            if len(self._events) > self.max_sources:
                self._events.popitem(last=False)
        q.append(ts)
        while q and q[0] < ts - self.window:
            q.popleft()
        return len(q)


class DnsDetector:
    def __init__(self) -> None:
        self._nx = NxdomainWindow()

    def __call__(self, flow: FlowRecord) -> list[Finding]:
        dns = flow.l7.dns if flow.l7 else None
        burst = 0
        if dns is not None and dns.rcode == "NXDOMAIN":
            burst = self._nx.observe(flow.src_ip, flow.ts_start)
        return detect(flow, nxdomain_burst=burst)


def detect(flow: FlowRecord, *, nxdomain_burst: int = 0) -> list[Finding]:
    dns = flow.l7.dns if flow.l7 else None
    if dns is None:
        return []
    labels = dns.qname.split(".")
    tld = labels[-1]
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    subdomain = ".".join(labels[:-2])
    findings: list[Finding] = []

    # --- DGA: the registrable label itself looks machine-generated -------------------
    ent = _entropy(sld)
    bigram = _bigram_score(sld)
    digits = sum(ch.isdigit() for ch in sld) / max(len(sld), 1)
    ev: list[tuple[str, float, str | float | None]] = []
    if len(sld) >= 12:
        ev.append(("long_registrable_label", 1.0, float(len(sld))))
    if ent > 3.5:
        ev.append(("label_entropy", (ent - 3.5) * 3.0, round(ent, 3)))
    if bigram < 0.6:
        ev.append(("rare_bigrams", (0.6 - bigram) * 6.0, round(bigram, 3)))
    run = _CONSONANT_RUN.search(sld)
    if run:
        ev.append(("consonant_run", 1.0, run.group(0)))
    if digits > 0.2:
        ev.append(("digit_ratio", digits * 3.0, round(digits, 3)))
    if dns.rcode == "NXDOMAIN":
        ev.append(("nxdomain", 1.5, dns.rcode))
    if nxdomain_burst >= 5:
        ev.append(("source_nxdomain_burst", min(nxdomain_burst / 5, 3.0), float(nxdomain_burst)))
    if tld in _SUSPICIOUS_TLDS:
        ev.append(("suspicious_tld", 0.8, tld))
    if ev:
        conf = calibrated([w for _, w, _ in ev], -4.5)
        if conf >= 0.3:
            findings.append(Finding(ThreatLabel.DGA, round(conf, 4), "dga", ev))

    # --- Tunnelling: data encoded into long subdomains ---------------------------------
    ev = []
    longest = max((len(x) for x in labels[:-2]), default=0)
    if len(subdomain) > 40:
        ev.append(("long_subdomain", min((len(subdomain) - 40) / 10, 4.0), float(len(subdomain))))
    if longest >= 30:
        ev.append(("long_label", 1.5, float(longest)))
    if any(_HEX_OR_B32.match(x) for x in labels[:-2]):
        ev.append(("encoded_label", 2.5, None))
    if dns.qtype in ("TXT", "NULL", "CNAME"):
        ev.append(("tunnel_qtype", 1.2, dns.qtype))
    if len(labels) > 5:
        ev.append(("many_labels", 0.8, float(len(labels))))
    if ev:
        conf = calibrated([w for _, w, _ in ev], -4.0)
        if conf >= 0.3:
            findings.append(Finding(ThreatLabel.DNS_TUNNEL, round(conf, 4), "dns_tunnel", ev))
    return findings
