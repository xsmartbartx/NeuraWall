"""Append-only, tamper-evident audit trail (blueprint §4.4 ``audit-trail``).

Each entry commits to the previous entry's hash, forming a chain. Altering,
reordering or deleting any past entry breaks verification from that point on.
Storage is the caller's concern; this module owns the chain arithmetic.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from neurawall.core.errors import IntegrityFailure
from neurawall.core.logging import redact
from neurawall.security.integrity import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


class AuditEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=1)
    ts: float
    actor: str = Field(max_length=200)
    action: str = Field(max_length=100)
    target: str = Field(max_length=200)
    detail: dict[str, Any] = {}
    prev_hash: str
    hash: str


def _digest(
    seq: int,
    ts: float,
    actor: str,
    action: str,
    target: str,
    detail: dict[str, Any],
    prev_hash: str,
) -> str:
    body = {
        "seq": seq,
        "ts": round(ts, 6),
        "actor": actor,
        "action": action,
        "target": target,
        "detail": detail,
        "prev_hash": prev_hash,
    }
    return sha256_hex(canonical_json(body))


def build_entry(
    *,
    prev: AuditEntry | None,
    ts: float,
    actor: str,
    action: str,
    target: str,
    detail: dict[str, Any] | None = None,
) -> AuditEntry:
    seq = (prev.seq + 1) if prev else 1
    prev_hash = prev.hash if prev else GENESIS_HASH
    clean = redact(detail or {})
    ts = round(ts, 6)
    return AuditEntry(
        seq=seq,
        ts=ts,
        actor=actor,
        action=action,
        target=target,
        detail=clean,
        prev_hash=prev_hash,
        hash=_digest(seq, ts, actor, action, target, clean, prev_hash),
    )


def verify_chain(entries: list[AuditEntry]) -> int:
    """Verify an ordered chain from genesis. Returns entry count or raises IntegrityFailure."""
    prev_hash = GENESIS_HASH
    for expected_seq, e in enumerate(entries, start=1):
        if e.seq != expected_seq:
            raise IntegrityFailure(f"audit chain gap at seq {expected_seq} (found {e.seq})")
        if e.prev_hash != prev_hash:
            raise IntegrityFailure(f"audit chain broken at seq {e.seq}: prev_hash mismatch")
        if _digest(e.seq, e.ts, e.actor, e.action, e.target, e.detail, e.prev_hash) != e.hash:
            raise IntegrityFailure(f"audit entry {e.seq} has been altered")
        prev_hash = e.hash
    return len(entries)
