"""SQL / command / template injection, path traversal and XSS in HTTP request metadata.

Evasion resistance: the path is iteratively URL-decoded (double-encoding), lower-cased,
SQL comments collapsed and whitespace normalised *before* any pattern is applied.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from neurawall.core.models import FlowRecord, ThreatLabel
from neurawall.modules.l7_classifier.detectors.base import Finding, calibrated

_SQL_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_WS = re.compile(r"\s+")

# (feature name, pattern, weight)
_SQLI = [
    ("sql_union_select", re.compile(r"\bunion\b\s*(all\s*)?\bselect\b"), 3.5),
    ("sql_tautology", re.compile(r"['\"]?\s*\b(or|and)\b\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*"), 2.2),
    ("sql_quote_comment", re.compile(r"['\"]\s*(--|#|;)"), 2.5),
    ("sql_stacked_query", re.compile(r";\s*(drop|delete|insert|update|alter|create|exec)\b"), 3.5),
    ("sql_time_based", re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\("), 3.0),
    ("sql_schema_probe", re.compile(r"\b(information_schema|sysobjects|sqlite_master)\b"), 3.0),
    ("sql_keywords", re.compile(r"\bselect\b.+\bfrom\b"), 1.5),
]
_CMDI = [
    ("cmd_separator_exec", re.compile(
        r"(;|\|\|?|&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|chmod|rm)\b"), 3.5),
    ("cmd_reverse_shell", re.compile(r"(\bnc\b.*-e|/bin/(ba)?sh|/dev/tcp/)"), 3.5),
    ("cmd_sensitive_file", re.compile(r"/etc/(passwd|shadow|hosts)|\bwin\.ini\b"), 2.0),
]
_TEMPLATE = [
    ("ssti_expression", re.compile(r"(\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\})"), 2.0),
    ("ssti_introspection", re.compile(r"__(class|globals|init|mro|subclasses|builtins)__"), 3.5),
    ("jndi_lookup", re.compile(r"\$\{jndi:"), 4.5),
]
_TRAVERSAL = [
    ("path_traversal", re.compile(r"(\.\./|\.\.\\){2,}"), 3.0),
    ("traversal_sensitive", re.compile(r"\.\./.*(etc/|windows/|boot\.ini|\.ssh)"), 2.0),
]
_XSS = [
    ("xss_script_tag", re.compile(r"<\s*script\b"), 3.5),
    ("xss_event_handler", re.compile(r"\bon(error|load|mouseover|focus)\s*="), 2.8),
    ("xss_js_uri", re.compile(r"javascript\s*:"), 2.5),
]
_SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|"
                         r"nuclei|zgrab|hydra)", re.I)

_GROUPS: list[tuple[ThreatLabel, list[tuple[str, re.Pattern[str], float]], float]] = [
    (ThreatLabel.SQL_INJECTION, _SQLI, -3.0),
    (ThreatLabel.COMMAND_INJECTION, _CMDI, -3.0),
    (ThreatLabel.TEMPLATE_INJECTION, _TEMPLATE, -3.0),
    (ThreatLabel.PATH_TRAVERSAL, _TRAVERSAL, -2.5),
    (ThreatLabel.XSS, _XSS, -3.0),
]


def normalise(path: str) -> str:
    s = path
    for _ in range(3):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    s = s.lower()
    s = _SQL_COMMENT.sub(" ", s)
    return _WS.sub(" ", s)


def detect(flow: FlowRecord) -> list[Finding]:
    http = flow.l7.http if flow.l7 else None
    if http is None:
        return []
    text = normalise(http.path)
    scanner = bool(http.user_agent and _SCANNER_UA.search(http.user_agent))
    findings: list[Finding] = []
    for label, patterns, bias in _GROUPS:
        evidence: list[tuple[str, float, str | float | None]] = []
        for name, pattern, weight in patterns:
            m = pattern.search(text)
            if m:
                evidence.append((name, weight, m.group(0)))
        if not evidence:
            continue
        weights = [w for _, w, _ in evidence]
        if scanner:
            evidence.append(("scanner_user_agent", 1.5, http.user_agent))
            weights.append(1.5)
        if http.status and http.status >= 500:
            evidence.append(("server_error_response", 0.5, float(http.status)))
            weights.append(0.5)
        conf = calibrated(weights, bias)
        if conf >= 0.3:
            findings.append(Finding(label, round(conf, 4), "injection", evidence))
    return findings
