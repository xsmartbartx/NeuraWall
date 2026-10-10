"""HTTP client for NEXORA Core (contracts C-ENT and C-EVENT).

One HTTPS call per operation with the installation's organisation API key, and an injectable
``httpx`` transport so no test talks to NEXORA. A control plane only ever *calls out*: it is
usually behind the customer's firewall, so nothing here needs an inbound connection.

Wire contract (what NEXORA's API must serve; see replica/architecture.md, N1 and N2):

* ``GET  {api_url}/v1/entitlements/neurawall`` -> ``{"org_id": str, "plan_id": str,
  "current_period_end": int | null}``. ``plan_id`` is the plan NEXORA has already resolved for
  the organisation (a lapsed or unpaid subscription arrives as ``community``).
* ``POST {api_url}/v1/events`` with ``{"events": [{"event_id", "type", "ts", "data"}]}``; the
  response is 2xx once every event is stored. ``event_id`` makes a retry idempotent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from neurawall.core.errors import RecoverableError

TIMEOUT = 10.0
#: A well-formed answer is a few hundred bytes; refuse anything much larger.
MAX_RESPONSE_BYTES = 64 * 1024


class NexoraError(RecoverableError):
    code = "nexora_error"


@dataclass(frozen=True)
class Entitlement:
    org_id: str
    plan_id: str
    current_period_end: float | None


class NexoraClient:
    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key:
            raise NexoraError("NEXORA API key is not configured")
        self._base = api_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}", "User-Agent": "neurawall"}
        self._transport = transport

    def _request(self, method: str, path: str, json: Any = None) -> httpx.Response:
        try:
            # No redirects: the key must only ever go to the configured host.
            with httpx.Client(
                timeout=TIMEOUT, transport=self._transport, follow_redirects=False
            ) as c:
                r = c.request(method, f"{self._base}{path}", headers=self._headers, json=json)
        except httpx.HTTPError as exc:
            raise NexoraError("NEXORA is unreachable") from exc
        if r.status_code in (401, 403):
            raise NexoraError("NEXORA rejected the API key")
        if r.status_code >= 400 or 300 <= r.status_code < 400:
            raise NexoraError(f"NEXORA answered {r.status_code}")
        if len(r.content) > MAX_RESPONSE_BYTES:
            raise NexoraError("NEXORA sent an oversized response")
        return r

    def fetch_entitlement(self) -> Entitlement:
        r = self._request("GET", "/v1/entitlements/neurawall")
        try:
            doc = r.json()
            org_id, plan_id = doc["org_id"], doc["plan_id"]
            end = doc.get("current_period_end")
        except (ValueError, KeyError, TypeError) as exc:
            raise NexoraError("NEXORA sent an unreadable entitlement") from exc
        if (
            not isinstance(org_id, str)
            or not org_id
            or not isinstance(plan_id, str)
            or isinstance(end, bool)
            or not (end is None or isinstance(end, int | float))
        ):
            raise NexoraError("NEXORA sent an unreadable entitlement")
        return Entitlement(org_id=org_id, plan_id=plan_id, current_period_end=end)

    def post_events(self, events: list[dict[str, Any]]) -> None:
        self._request("POST", "/v1/events", json={"events": events})
