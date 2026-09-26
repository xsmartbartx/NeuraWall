"""Signed policy bundles and staged rollout (blueprint §6.2, §8)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from neurawall.core.errors import IntegrityFailure
from neurawall.core.models import PolicyBundle, SignedEnvelope
from neurawall.security.integrity import Signer, sign_payload, verify_envelope


def sign_bundle(bundle: PolicyBundle, signer: Signer) -> SignedEnvelope:
    return sign_payload(bundle.model_dump(mode="json"), signer)


def open_bundle(envelope: SignedEnvelope, trusted_keys: dict[str, Ed25519PublicKey],
                *, min_version: int = 0) -> PolicyBundle:
    """Verify signature, then schema, then monotonic version (anti-rollback)."""
    payload = verify_envelope(envelope, trusted_keys)
    try:
        bundle = PolicyBundle.model_validate(payload)
    except ValueError as exc:
        raise IntegrityFailure("signed bundle does not satisfy the bundle schema") from exc
    if bundle.version < min_version:
        raise IntegrityFailure(
            f"bundle version {bundle.version} is older than applied version {min_version}")
    return bundle


# Canary 5% -> 25% -> 100% (blueprint §6.2).
DEFAULT_STAGES: tuple[int, ...] = (5, 25, 100)


def node_bucket(node_id: str, salt: str) -> int:
    """Stable 0..99 bucket for a node; salted per rollout so canaries rotate."""
    digest = hashlib.sha256(f"{salt}:{node_id}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % 100


@dataclass(frozen=True)
class RolloutState:
    version: int
    stage_index: int
    stages: tuple[int, ...] = DEFAULT_STAGES

    @property
    def percent(self) -> int:
        return self.stages[self.stage_index]

    @property
    def complete(self) -> bool:
        return self.stage_index >= len(self.stages) - 1

    def includes(self, node_id: str) -> bool:
        return node_bucket(node_id, f"v{self.version}") < self.percent

    def advance(self) -> RolloutState:
        return RolloutState(self.version, min(self.stage_index + 1, len(self.stages) - 1), self.stages)


def should_rollback(*, baseline_block_rate: float, canary_block_rate: float,
                    max_increase: float = 0.02) -> bool:
    """Auto-rollback when the canary blocks materially more traffic than the baseline."""
    return canary_block_rate - baseline_block_rate > max_increase
