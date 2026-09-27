"""Stripe integration: hosted Checkout, Customer Portal, signed webhooks.

Mirrors Vigilo's adapter: no SDK, one HTTPS call per operation, and an
injectable ``httpx`` transport so no test talks to Stripe.

NeuraWall shares its Stripe account with the rest of the NEXORA platform, so
every subscription event on that account reaches this webhook. Only
subscriptions carrying ``metadata.neurawall_installation`` equal to *this*
installation's id, on one of *this* installation's prices, are applied;
anything else belongs to another product (or another NeuraWall install) and is
ignored — never an error, since a non-2xx makes Stripe retry for days and then
disable the endpoint for every product.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from neurawall.core.errors import RecoverableError, ValidationFailure

API = "https://api.stripe.com/v1"
TIMEOUT = 15.0
#: Stripe's own libraries use five minutes.
SIGNATURE_TOLERANCE_SECONDS = 300
METADATA_KEY = "neurawall_installation"

_EVENTS = frozenset(
    {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
    }
)
# Stripe keeps retrying a failed renewal while `past_due`, then cancels; access
# continues through that window rather than dropping on the first declined card.
_ACTIVE = frozenset({"active", "trialing", "past_due"})


class BillingProviderError(RecoverableError):
    code = "billing_provider_error"


class NotOurEvent(ValidationFailure):
    """A well-formed event that belongs to another product or installation."""

    code = "billing_event_ignored"


@dataclass(frozen=True)
class SubscriptionEvent:
    event_type: str
    subscription_id: str
    customer_id: str | None
    plan_id: str
    status: str  # "active" | "canceled"
    period_end: datetime | None


def verify_signature(
    raw_body: bytes, header: str, secret: str, *, now: float | None = None
) -> bool:
    """`Stripe-Signature: t=<unix>,v1=<hex hmac-sha256 of "t.body">[,v1=...]`."""
    if not secret:
        raise BillingProviderError("Stripe webhook secret is not configured")
    timestamp: str | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, sep, value = part.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if timestamp is None or not signatures:
        return False
    try:
        age = (time.time() if now is None else now) - int(timestamp)
    except ValueError:
        return False
    if abs(age) > SIGNATURE_TOLERANCE_SECONDS:
        return False
    expected = hmac.new(
        secret.encode(), timestamp.encode() + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in signatures)


def parse_event(raw_body: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationFailure("Stripe webhook body was not valid JSON") from exc
    if not isinstance(doc, dict):
        raise ValidationFailure("Stripe webhook body was not an object")
    return doc


def interpret_event(
    payload: dict[str, Any], *, installation_id: str, plan_by_price: dict[str, str]
) -> SubscriptionEvent:
    """Pure. Raises :class:`NotOurEvent` for anything this installation must not apply."""
    event_type = payload.get("type")
    if event_type not in _EVENTS:
        raise NotOurEvent(f"unhandled event type {event_type!r}")
    try:
        sub = payload["data"]["object"]
        if (sub.get("metadata") or {}).get(METADATA_KEY) != installation_id:
            raise NotOurEvent("subscription belongs to another product or installation")
        item = sub["items"]["data"][0]
        plan_id = plan_by_price.get(item["price"]["id"])
        if plan_id is None:
            raise NotOurEvent("price is not a NeuraWall plan price")
        # Newer Stripe API versions moved the period onto the subscription item.
        period_end = item.get("current_period_end") or sub.get("current_period_end")
        active = event_type != "customer.subscription.deleted" and sub["status"] in _ACTIVE
        customer = sub.get("customer")
        return SubscriptionEvent(
            event_type=event_type,
            subscription_id=str(sub["id"]),
            customer_id=customer if isinstance(customer, str) else None,
            plan_id=plan_id,
            status="active" if active else "canceled",
            period_end=datetime.fromtimestamp(int(period_end), UTC) if period_end else None,
        )
    except NotOurEvent:
        raise
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        # A recognized event with a malformed payload is discarded whole.
        raise NotOurEvent("malformed subscription payload") from exc


class StripeClient:
    def __init__(
        self,
        secret_key: str,
        *,
        transport: httpx.BaseTransport | None = None,
        portal_configuration_id: str | None = None,
    ) -> None:
        if not secret_key:
            raise BillingProviderError("Stripe secret key is not configured")
        self._auth = (secret_key, "")
        self._transport = transport
        self._portal_configuration = portal_configuration_id

    def _post(self, path: str, form: dict[str, str]) -> dict[str, Any]:
        try:
            with httpx.Client(timeout=TIMEOUT, transport=self._transport) as c:
                r = c.post(f"{API}{path}", data=form, auth=self._auth)
        except httpx.HTTPError as exc:
            raise BillingProviderError("Stripe request failed") from exc
        if r.status_code >= 400:
            raise BillingProviderError(f"Stripe rejected the request ({r.status_code})")
        return r.json()  # type: ignore[no-any-return]

    def create_checkout(
        self,
        *,
        price_id: str,
        installation_id: str,
        customer_email: str,
        success_url: str,
        cancel_url: str,
        plan_id: str,
    ) -> str:
        doc = self._post(
            "/checkout/sessions",
            {
                "mode": "subscription",
                "line_items[0][price]": price_id,
                "line_items[0][quantity]": "1",
                "customer_email": customer_email,
                "client_reference_id": installation_id,
                # Copied onto the Subscription, so every customer.subscription.* event
                # carries it back — and marks it as this installation's on a shared account.
                f"subscription_data[metadata][{METADATA_KEY}]": installation_id,
                "subscription_data[metadata][neurawall_plan]": plan_id,
                "allow_promotion_codes": "true",
                "success_url": success_url,
                "cancel_url": cancel_url,
            },
        )
        url = doc.get("url")
        if not url:
            raise BillingProviderError("Stripe returned no checkout URL")
        return str(url)

    def create_portal(self, *, customer_id: str, return_url: str) -> str:
        form = {"customer": customer_id, "return_url": return_url}
        if self._portal_configuration:
            form["configuration"] = self._portal_configuration
        url = self._post("/billing_portal/sessions", form).get("url")
        if not url:
            raise BillingProviderError("Stripe returned no portal URL")
        return str(url)
