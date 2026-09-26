"""Policy engine: the sole component permitted to turn signals into enforcement actions."""

from neurawall.modules.policy_engine.arbitration import PolicyEngine
from neurawall.modules.policy_engine.bundle import (
    RolloutState,
    open_bundle,
    should_rollback,
    sign_bundle,
)
from neurawall.modules.policy_engine.ruleset import Evidence, analyze_hygiene, match_flow
from neurawall.modules.policy_engine.simulator import simulate

__all__ = [
    "Evidence",
    "PolicyEngine",
    "RolloutState",
    "analyze_hygiene",
    "match_flow",
    "open_bundle",
    "should_rollback",
    "sign_bundle",
    "simulate",
]
