from __future__ import annotations

import math
from dataclasses import dataclass, field

from neurawall.core.models import Attribution, ThreatLabel


@dataclass
class Finding:
    label: ThreatLabel
    confidence: float
    detector: str
    evidence: list[tuple[str, float, str | float | None]] = field(default_factory=list)

    def attributions(self) -> list[Attribution]:
        top = sorted(self.evidence, key=lambda e: abs(e[1]), reverse=True)[:8]
        return [Attribution(feature=f[:64], contribution=round(w, 4),
                            value=(v[:120] if isinstance(v, str) else v)) for f, w, v in top]


def logistic(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


def calibrated(weights: list[float], bias: float) -> float:
    """Map summed evidence weights to a probability (hand-calibrated logistic)."""
    return logistic(sum(weights) + bias)
