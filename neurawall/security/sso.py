"""Single sign-on from a Clerk session token (opt-in; see `AuthSettings.sso_*`).

Clerk only proves *who someone is*. Everything NeuraWall enforces — the user
row, its role, the four-eyes rule, deactivation — stays in NeuraWall: a verified
identity is mapped to an existing, active user and signs in with that user's own
role. This module only verifies the token; the control plane decides whether to
create a user (`auth.sso_jit`) and never takes a role from the token.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWKClient

from neurawall.core.errors import PolicyViolation

GetSigningKey = Callable[[str], Any]
_ALGORITHMS = ["RS256"]


@dataclass(frozen=True)
class SsoIdentity:
    email: str
    org_id: str | None
    #: The identity provider's stable user id (`sub`); survives email changes.
    subject: str
    #: True only when the token explicitly says the email is verified.
    email_verified: bool
    name: str


@lru_cache(maxsize=4)
def _jwk_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url)


def verify_sso_token(
    token: str,
    *,
    jwks_url: str,
    issuer: str | None = None,
    audience: str | None = None,
    required_org_id: str | None = None,
    get_signing_key: GetSigningKey | None = None,
) -> SsoIdentity:
    """Verify signature, expiry and (optionally) issuer and organisation, and
    return the identity. Every failure is the same generic `PolicyViolation` so
    a caller cannot tell which check rejected the token."""
    denied = PolicyViolation("single sign-on was not accepted")
    # An env var set to the empty string means "not configured", not "must equal ''".
    issuer, audience, required_org_id = issuer or None, audience or None, required_org_id or None
    try:
        key = (
            get_signing_key(token)
            if get_signing_key
            else _jwk_client(jwks_url).get_signing_key_from_jwt(token).key
        )
        payload = jwt.decode(
            token,
            key,
            algorithms=_ALGORITHMS,
            issuer=issuer,
            audience=audience,
            options={"verify_aud": audience is not None, "require": ["exp", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise denied from exc

    email = payload.get("email")
    if not isinstance(email, str) or not email.strip() or len(email) > 254:
        raise denied  # 254 is the users.email column; refuse rather than fail on insert

    raw_nested = payload.get("o")
    nested: dict[str, Any] = raw_nested if isinstance(raw_nested, dict) else {}
    org_id = payload.get("org_id") or nested.get("id") or None
    if required_org_id and org_id != required_org_id:
        raise denied

    subject = str(payload["sub"])
    if len(subject) > 64:
        raise denied  # stored in a 64 character column: refuse rather than truncate into a collision
    raw_name = payload.get("name")
    return SsoIdentity(
        email=email.strip().lower(),
        org_id=str(org_id) if org_id else None,
        subject=subject,
        email_verified=payload.get("email_verified") is True,
        name=raw_name.strip()[:120] if isinstance(raw_name, str) else "",
    )
