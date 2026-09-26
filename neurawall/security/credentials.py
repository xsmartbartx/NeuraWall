"""Password hashing, access tokens and node/API keys."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from neurawall.core.errors import PolicyViolation

_HASHER = PasswordHasher()
_JWT_ALG = "HS256"
API_KEY_PREFIX = "nwk_"
MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    validate_password_strength(password)
    return _HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PolicyViolation(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes < 3:
        raise PolicyViolation("password must mix at least three of: lower, upper, digit, symbol")


def issue_token(*, subject: str, role: str, secret: str, ttl_seconds: int,
                extra: dict[str, Any] | None = None) -> str:
    now = int(time.time())
    claims = {"sub": subject, "role": role, "iat": now, "exp": now + ttl_seconds,
              "jti": secrets.token_hex(8), **(extra or {})}
    return jwt.encode(claims, secret, algorithm=_JWT_ALG)


def decode_token(token: str, *, secret: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=[_JWT_ALG], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as exc:
        raise PolicyViolation("invalid or expired token") from exc


def generate_api_key() -> tuple[str, str]:
    """Return ``(plaintext, sha256_hash)``. Only the hash is ever stored."""
    plaintext = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return plaintext, hash_api_key(plaintext)


def hash_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def api_key_matches(plaintext: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_api_key(plaintext), stored_hash)
