import hashlib
import hmac
import json
import time

import httpx
import pytest

from neurawall.modules.billing import (
    PLANS,
    BillingProviderError,
    NotOurEvent,
    PlanId,
    StripeClient,
    check_nodes,
    entitlements,
    interpret_event,
    verify_signature,
)

INSTALL = "nwi_test"
PRICES = {"price_pro_m": "pro", "price_biz_y": "business"}


def sign(body: bytes, secret: str, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def event(
    kind="customer.subscription.updated",
    *,
    install=INSTALL,
    price="price_pro_m",
    status="active",
    period_end=2_000_000_000,
):
    return {
        "type": kind,
        "data": {
            "object": {
                "id": "sub_1",
                "customer": "cus_1",
                "status": status,
                "metadata": {"neurawall_installation": install} if install else {},
                "items": {"data": [{"price": {"id": price}, "current_period_end": period_end}]},
            }
        },
    }


def test_plans_match_financial_model():
    assert [
        (p.name, p.price_cents_month, p.nodes_limit, p.retention_days) for p in PLANS.values()
    ] == [
        ("Community", 0, 1, 7),
        ("Pro", 14900, 5, 7),
        ("Business", 49900, 25, 30),
        ("Enterprise", 300000, 100, 90),
        ("Enterprise Dedicated", 500000, None, None),
    ]
    assert all(
        p.price_cents_year == 10 * p.price_cents_month for p in PLANS.values() if p.self_serve
    )  # two months free
    assert not PLANS[PlanId.COMMUNITY].llm_advisor_allowed


def test_entitlements_fail_closed():
    assert entitlements(None).plan_id == PlanId.COMMUNITY
    assert entitlements("platinum").plan_id == PlanId.COMMUNITY
    assert entitlements("business").plan_id == PlanId.BUSINESS


def test_node_quota():
    assert check_nodes(0, PLANS[PlanId.COMMUNITY]).allowed
    d = check_nodes(1, PLANS[PlanId.COMMUNITY])
    assert not d.allowed and "Community plan includes 1 enforcement node;" in d.reason
    assert check_nodes(10_000, PLANS[PlanId.DEDICATED]).allowed


def test_signature_verification():
    body = b'{"a":1}'
    assert verify_signature(body, sign(body, "whsec"), "whsec")
    assert not verify_signature(body, sign(body, "other"), "whsec")
    assert not verify_signature(body + b" ", sign(body, "whsec"), "whsec")
    assert not verify_signature(body, sign(body, "whsec", int(time.time()) - 600), "whsec")
    assert not verify_signature(body, "garbage", "whsec")
    with pytest.raises(BillingProviderError):
        verify_signature(body, sign(body, "x"), "")


def test_interpret_own_subscription():
    ev = interpret_event(event(), installation_id=INSTALL, plan_by_price=PRICES)
    assert (ev.plan_id, ev.status, ev.customer_id) == ("pro", "active", "cus_1")
    assert ev.period_end is not None
    past_due = interpret_event(
        event(status="past_due"), installation_id=INSTALL, plan_by_price=PRICES
    )
    assert past_due.status == "active"
    gone = interpret_event(
        event("customer.subscription.deleted"), installation_id=INSTALL, plan_by_price=PRICES
    )
    assert gone.status == "canceled"
    unpaid = interpret_event(event(status="unpaid"), installation_id=INSTALL, plan_by_price=PRICES)
    assert unpaid.status == "canceled"


@pytest.mark.parametrize(
    "payload",
    [
        event(install=None),  # Vigilo / NEXORA subscription on the shared account
        event(install="nwi_other"),  # another NeuraWall installation
        event(price="price_vigilo"),  # not one of our prices
        {"type": "invoice.paid", "data": {}},  # unhandled event type
        {
            "type": "customer.subscription.updated",
            "data": {"object": {"metadata": {"neurawall_installation": INSTALL}}},
        },  # malformed
    ],
)
def test_foreign_or_malformed_events_are_ignored(payload):
    with pytest.raises(NotOurEvent):
        interpret_event(payload, installation_id=INSTALL, plan_by_price=PRICES)


def test_checkout_and_portal_requests():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, dict(httpx.QueryParams(request.content.decode()))))
        if request.url.path.endswith("/checkout/sessions"):
            return httpx.Response(200, json={"url": "https://checkout.stripe.com/c/1"})
        return httpx.Response(200, json={"url": "https://billing.stripe.com/p/1"})

    client = StripeClient("sk_test", transport=httpx.MockTransport(handler))
    assert client.create_checkout(
        price_id="price_pro_m",
        installation_id=INSTALL,
        customer_email="a@b.c",
        success_url="s",
        cancel_url="c",
        plan_id="pro",
    ).startswith("https://checkout.stripe.com")
    path, form = seen[0]
    assert path == "/v1/checkout/sessions" and form["mode"] == "subscription"
    assert form["subscription_data[metadata][neurawall_installation]"] == INSTALL
    assert form["line_items[0][price]"] == "price_pro_m"
    assert client.create_portal(customer_id="cus_1", return_url="r").startswith("https://billing")
    assert seen[1][1] == {"customer": "cus_1", "return_url": "r"}


def test_stripe_errors_are_recoverable():
    client = StripeClient("sk_test", transport=httpx.MockTransport(lambda r: httpx.Response(402)))
    with pytest.raises(BillingProviderError):
        client.create_portal(customer_id="cus_1", return_url="r")
    json.dumps({})


def test_empty_env_values_mean_billing_disabled():
    from neurawall.core.config import load_settings

    s = load_settings(
        environment="test",
        billing={
            "stripe_secret_key": "",
            "stripe_webhook_secret": "",
            "price_pro_month": "",
            "plan": "business",
        },
    )
    assert not s.billing.self_serve_enabled and s.billing.plan_by_price() == {}
    assert s.billing.plan == "business"
