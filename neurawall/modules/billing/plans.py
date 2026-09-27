"""Plan table and entitlement resolution.

Plans mirror the "Pricing" sheet of NeuraWall_financial_marketing_model_2026.xlsx
and the public pricing page (onenexora.com/pricing). A subscription belongs to
the *installation* (one control plane = one organisation), not to a user.

`None` on a limit means unlimited. Every plan sets every limit explicitly: a
dataclass default silently meaning "unlimited" on the free plan is exactly the
bug to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class PlanId(StrEnum):
    COMMUNITY = "community"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    DEDICATED = "enterprise_dedicated"


@dataclass(frozen=True)
class Plan:
    plan_id: PlanId
    name: str
    nodes_limit: int | None
    retention_days: int | None
    llm_advisor_allowed: bool
    support: str
    #: Self-serve through Stripe Checkout. Dedicated is quoted and licensed by sales.
    self_serve: bool
    # Display prices in cents. What a customer is charged is the Stripe Price
    # configured for the plan (billing.price_ids) — keep them in step.
    price_cents_month: int
    price_cents_year: int


PLANS: dict[PlanId, Plan] = {
    PlanId.COMMUNITY: Plan(
        plan_id=PlanId.COMMUNITY,
        name="Community",
        nodes_limit=1,
        retention_days=7,
        llm_advisor_allowed=False,
        support="Community",
        self_serve=False,
        price_cents_month=0,
        price_cents_year=0,
    ),
    PlanId.PRO: Plan(
        plan_id=PlanId.PRO,
        name="Pro",
        nodes_limit=5,
        retention_days=7,
        llm_advisor_allowed=True,
        support="Email, 2 business days",
        self_serve=True,
        price_cents_month=14900,
        price_cents_year=149000,
    ),
    PlanId.BUSINESS: Plan(
        plan_id=PlanId.BUSINESS,
        name="Business",
        nodes_limit=25,
        retention_days=30,
        llm_advisor_allowed=True,
        support="Priority, 1 business day",
        self_serve=True,
        price_cents_month=49900,
        price_cents_year=499000,
    ),
    PlanId.ENTERPRISE: Plan(
        plan_id=PlanId.ENTERPRISE,
        name="Enterprise",
        nodes_limit=100,
        retention_days=90,
        llm_advisor_allowed=True,
        support="SLA, priority",
        self_serve=True,
        price_cents_month=300000,
        price_cents_year=3000000,
    ),
    PlanId.DEDICATED: Plan(
        plan_id=PlanId.DEDICATED,
        name="Enterprise Dedicated",
        nodes_limit=None,
        retention_days=None,
        llm_advisor_allowed=True,
        support="SLA + onboarding",
        self_serve=False,
        price_cents_month=500000,
        price_cents_year=0,
    ),
}


def entitlements(plan_id: str | None) -> Plan:
    """Unknown or missing plan ids resolve to Community: fail closed, never open."""
    try:
        return PLANS[PlanId(plan_id or "")]
    except ValueError:
        return PLANS[PlanId.COMMUNITY]


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    current: int
    limit: int | None
    reason: str


def check_nodes(current: int, plan: Plan, adding: int = 1) -> QuotaDecision:
    """Pure comparison; the caller counts current usage fresh every time."""
    if plan.nodes_limit is None:
        return QuotaDecision(True, current, None, "unlimited")
    allowed = current + adding <= plan.nodes_limit
    reason = (
        "within quota"
        if allowed
        else (
            f"the {plan.name} plan includes {plan.nodes_limit} enforcement node"
            f"{'s' if plan.nodes_limit != 1 else ''}; upgrade to enroll more"
        )
    )
    return QuotaDecision(allowed, current, plan.nodes_limit, reason)
