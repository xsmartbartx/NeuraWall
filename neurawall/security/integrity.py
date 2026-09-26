"""Signature creation and verification for policy bundles (blueprint §4.4 ``integrity``).

Bundles are signed with Ed25519 over a canonical JSON encoding. Nodes verify the
signature independently of transport security, against a pinned public key.

The :class:`Signer` protocol keeps the private-key backend pluggable: the default
:class:`FileSigner` keeps the key on disk with 0600 permissions; an HSM/KMS signer
implements the same two methods.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from neurawall.core.errors import IntegrityFailure
from neurawall.core.models import SignedEnvelope


def canonical_json(payload: Any) -> bytes:
    """Deterministic encoding: sorted keys, no whitespace, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      default=str).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_id_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256_hex(raw)[:16]


def public_key_to_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def load_public_key(pem: str | bytes) -> Ed25519PublicKey:
    data = pem.encode() if isinstance(pem, str) else pem
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise IntegrityFailure("invalid public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise IntegrityFailure("public key is not Ed25519")
    return key


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...

    def public_key_pem(self) -> str: ...

    def sign(self, data: bytes) -> bytes: ...


class FileSigner:
    """Ed25519 key persisted as PKCS#8 PEM. Generated on first use."""

    def __init__(self, path: Path) -> None:
        self.path = path
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise IntegrityFailure(f"signing key at {path} is not Ed25519")
            self._key = key
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._key = Ed25519PrivateKey.generate()
            pem = self._key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            path.touch(mode=0o600)
            path.write_bytes(pem)
        self._key_id = key_id_for(self._key.public_key())

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_pem(self) -> str:
        return public_key_to_pem(self._key.public_key())

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


class EphemeralSigner(FileSigner):
    """In-memory key for tests and demos."""

    def __init__(self) -> None:  # noqa: D107 - intentionally skips file handling
        self._key = Ed25519PrivateKey.generate()
        self._key_id = key_id_for(self._key.public_key())


def sign_payload(payload: dict[str, Any], signer: Signer) -> SignedEnvelope:
    signature = signer.sign(canonical_json(payload))
    return SignedEnvelope(
        payload=payload, signature=base64.b64encode(signature).decode(), key_id=signer.key_id
    )


def verify_envelope(envelope: SignedEnvelope, trusted_keys: dict[str, Ed25519PublicKey]) -> dict[str, Any]:
    """Verify and return the payload. Raises :class:`IntegrityFailure` on any mismatch."""
    key = trusted_keys.get(envelope.key_id)
    if key is None:
        raise IntegrityFailure(f"signature key {envelope.key_id!r} is not trusted")
    try:
        sig = base64.b64decode(envelope.signature, validate=True)
        key.verify(sig, canonical_json(envelope.payload))
    except (InvalidSignature, ValueError) as exc:
        raise IntegrityFailure("bundle signature verification failed") from exc
    return dict(envelope.payload)
