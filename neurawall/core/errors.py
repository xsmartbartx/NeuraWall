"""Typed error hierarchy (blueprint §4.1).

Callers distinguish *recoverable* faults (retry / degrade) from *policy violations*
(a request that must be refused) and *integrity failures* (tampering; never retried).
"""

from __future__ import annotations


class NeuraWallError(Exception):
    """Base class for all NeuraWall errors."""

    code = "neurawall_error"

    def __init__(self, message: str, *, detail: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class RecoverableError(NeuraWallError):
    """A transient fault: the operation may be retried or the component degraded."""

    code = "recoverable"


class ValidationFailure(NeuraWallError):
    """Input crossed a boundary without satisfying its schema or constraints."""

    code = "validation_failure"


class PolicyViolation(NeuraWallError):
    """The request is well-formed but not permitted (authz, approval gate, blast radius)."""

    code = "policy_violation"


class IntegrityFailure(NeuraWallError):
    """A signature, hash chain or bundle failed verification. Never retried."""

    code = "integrity_failure"


class NotFound(NeuraWallError):
    code = "not_found"


class ModelFault(NeuraWallError):
    """A model produced output outside its contract (e.g. out-of-range score).

    Per blueprint §9.3(3): an out-of-range score is a fault, not a verdict.
    """

    code = "model_fault"
