"""Starter policy pack seeded on first boot. Conservative: most rules start alert-only."""

from __future__ import annotations

from neurawall.core.models import Action, Direction, Protocol, Rule, RuleMatch, RuleMode, ThreatLabel


def starter_rules() -> list[Rule]:
    def r(n: int, **kw: object) -> Rule:
        return Rule(id=f"R-{n:06d}", created_by="starter-pack", approved_by="starter-pack", **kw)  # type: ignore[arg-type]

    return [
        r(1, name="Block high-confidence web injection", priority=100, action=Action.DROP,
          match=RuleMatch(labels=[ThreatLabel.SQL_INJECTION, ThreatLabel.COMMAND_INJECTION,
                                  ThreatLabel.TEMPLATE_INJECTION, ThreatLabel.PATH_TRAVERSAL],
                          min_label_confidence=0.9),
          rationale="Injection payloads detected with >=90% confidence have no legitimate use; "
                    "blocking them protects web applications from exploitation."),
        r(2, name="Block inbound Telnet and SMBv1-era ports", priority=110, action=Action.DROP,
          match=RuleMatch(directions=[Direction.INBOUND], protocols=[Protocol.TCP],
                          dst_ports=[23, 139, 445, 3389]),
          rationale="Telnet, NetBIOS/SMB and RDP should never be reachable from the internet."),
        r(3, name="Quarantine hosts beaconing to C2", priority=150, action=Action.QUARANTINE,
          mode=RuleMode.ALERT_ONLY,
          match=RuleMatch(labels=[ThreatLabel.C2_BEACON], min_label_confidence=0.85),
          rationale="Low-jitter periodic callbacks indicate an implant. Starts alert-only: "
                    "promote to enforce after reviewing detections in your environment."),
        r(4, name="Block DNS tunnelling", priority=160, action=Action.DROP, mode=RuleMode.ALERT_ONLY,
          match=RuleMatch(labels=[ThreatLabel.DNS_TUNNEL], min_label_confidence=0.9),
          rationale="Data encoded in DNS queries bypasses egress controls."),
        r(5, name="Alert on DGA lookups", priority=170, action=Action.ALERT,
          match=RuleMatch(labels=[ThreatLabel.DGA], min_label_confidence=0.8),
          rationale="Algorithmically generated domains are a strong malware indicator."),
        r(6, name="Block large exfiltration to risky destinations", priority=180,
          action=Action.DROP, mode=RuleMode.ALERT_ONLY,
          match=RuleMatch(labels=[ThreatLabel.EXFILTRATION], min_label_confidence=0.9),
          rationale="Large asymmetric uploads to unknown destinations indicate data theft."),
        r(7, name="Rate-limit port scans", priority=200, action=Action.RATE_LIMIT,
          mode=RuleMode.ALERT_ONLY, match=RuleMatch(min_anomaly_score=0.95,
                                                    directions=[Direction.INTERNAL]),
          rationale="Extreme Tier 1 anomaly scores on internal traffic usually mean scanning."),
    ]
