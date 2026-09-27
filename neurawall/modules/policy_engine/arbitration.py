"""Verdict arbitration — the only place signals become enforcement actions.

Invariants (blueprint §1.3, §8):

* Models produce *signals*; only a matching rule produces a blocking *action*.
  With no matching rule, the strongest outcome a model can cause is an ALERT.
* Every enforced blocking verdict references exactly one rule id.
* ``alert_only`` rules report what they would have done but never enforce.
"""

from __future__ import annotations

from neurawall.core.models import Action, PolicyBundle, RuleMode, ThreatLabel, Verdict
from neurawall.core.telemetry import REGISTRY
from neurawall.modules.policy_engine.ruleset import Evidence, match_flow, order_rules

_verdicts = REGISTRY.counter("neurawall_verdicts_total", "Verdicts by action and enforcement")
_eval_latency = REGISTRY.histogram("neurawall_arbitration_seconds", "Policy evaluation latency")


class PolicyEngine:
    def __init__(self, bundle: PolicyBundle) -> None:
        self.bundle = bundle
        self._rules = order_rules(bundle.rules)

    @property
    def version(self) -> int:
        return self.bundle.version

    def evaluate(self, ev: Evidence) -> Verdict:
        with _eval_latency.time():
            verdict = self._evaluate(ev)
        _verdicts.inc(action=verdict.action.value, enforced=str(verdict.enforced).lower())
        return verdict

    def _evaluate(self, ev: Evidence) -> Verdict:
        score = ev.anomaly.score if ev.anomaly else None
        labels = [c.label for c in ev.malicious_labels]
        signal_reasons = self._signal_reasons(ev)

        for rule in self._rules:
            if not match_flow(rule.match, ev):
                continue
            if rule.mode == RuleMode.ALERT_ONLY and rule.action != Action.ALLOW:
                return Verdict(
                    flow_id=ev.flow.flow_id,
                    action=Action.ALERT,
                    rule_id=rule.id,
                    enforced=False,
                    reasons=[
                        f"{rule.id} '{rule.name}' matched (alert-only; would {rule.action})",
                        *signal_reasons,
                    ],
                    anomaly_score=score,
                    labels=labels,
                )
            return Verdict(
                flow_id=ev.flow.flow_id,
                action=rule.action,
                rule_id=rule.id,
                enforced=rule.action.is_blocking,
                reasons=[f"{rule.id} '{rule.name}' matched", *signal_reasons],
                anomaly_score=score,
                labels=labels,
            )

        # No rule matched: models may raise an alert, never block.
        if self._signals_warrant_alert(ev):
            return Verdict(
                flow_id=ev.flow.flow_id,
                action=Action.ALERT,
                rule_id=None,
                enforced=False,
                reasons=[
                    "no rule matched; inference signals exceed alert threshold",
                    *signal_reasons,
                ],
                anomaly_score=score,
                labels=labels,
            )
        return Verdict(
            flow_id=ev.flow.flow_id,
            action=self.bundle.default_action,
            rule_id=None,
            enforced=False,
            reasons=["default policy"],
            anomaly_score=score,
            labels=labels,
        )

    def _signals_warrant_alert(self, ev: Evidence) -> bool:
        if ev.anomaly and ev.anomaly.score >= self.bundle.anomaly_alert_threshold:
            return True
        return any(
            c.label != ThreatLabel.BENIGN and c.confidence >= self.bundle.classifier_alert_threshold
            for c in ev.classifications
        )

    @staticmethod
    def _signal_reasons(ev: Evidence) -> list[str]:
        out: list[str] = []
        if ev.anomaly and ev.anomaly.score >= 0.5:
            feats = ", ".join(a.feature for a in ev.anomaly.top_features[:3])
            out.append(f"anomaly score {ev.anomaly.score:.2f} ({feats})")
        for c in ev.malicious_labels[:3]:
            out.append(f"{c.detector}: {c.label} @ {c.confidence:.2f}")
        return out
