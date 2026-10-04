"""Single sign-on from a Clerk session token (opt-in; see `AuthSettings.sso_*`).

Clerk only proves *who someone is*. Everything NeuraWall enforces — the user
row, its role, the four-eyes rule, deactivation — stays in NeuraWall: a verified
identity is mapped to an existing, active user by email and signs in with that
user's own role. Nothing here creates users or grants roles.
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
    if not isinstance(email, str) or not email.strip():
        raise denied

    raw_nested = payload.get("o")
    nested: dict[str, Any] = raw_nested if isinstance(raw_nested, dict) else {}
    org_id = payload.get("org_id") or nested.get("id") or None
    if required_org_id and org_id != required_org_id:
        raise denied

    return SsoIdentity(email=email.strip().lower(), org_id=str(org_id) if org_id else None)
