"""Role definitions and authorization checks (blueprint §4.4 ``rbac``).

Approval of enforcement changes is a separate permission from authoring them, and
the four-eyes rule forbids approving your own change (blueprint §9.2: "rule changes
require human approval with separate credentials").
"""

from __future__ import annotations

from enum import StrEnum

from neurawall.core.errors import PolicyViolation


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    APPROVER = "approver"
    ADMIN = "admin"


class Permission(StrEnum):
    READ = "read"
    TRIAGE_ALERTS = "alerts:triage"
    USE_ADVISOR = "advisor:use"
    AUTHOR_RULES = "rules:author"
    APPROVE_RULES = "rules:approve"
    MANAGE_FLEET = "fleet:manage"
    MANAGE_USERS = "users:manage"
    READ_AUDIT = "audit:read"
    MANAGE_SETTINGS = "settings:manage"
    MANAGE_INTEGRATIONS = "integrations:manage"


_GRANTS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.READ}),
    Role.ANALYST: frozenset({Permission.READ, Permission.TRIAGE_ALERTS, Permission.USE_ADVISOR}),
    Role.OPERATOR: frozenset(
        {
            Permission.READ,
            Permission.TRIAGE_ALERTS,
            Permission.USE_ADVISOR,
            Permission.AUTHOR_RULES,
            Permission.MANAGE_FLEET,
        }
    ),
    Role.APPROVER: frozenset(
        {
            Permission.READ,
            Permission.TRIAGE_ALERTS,
            Permission.USE_ADVISOR,
            Permission.APPROVE_RULES,
            Permission.READ_AUDIT,
        }
    ),
    Role.ADMIN: frozenset(Permission),
}


def permissions_for(role: Role) -> frozenset[Permission]:
    return _GRANTS[role]


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in _GRANTS[role]


def authorize(role: Role, permission: Permission) -> None:
    if not has_permission(role, permission):
        raise PolicyViolation(f"role '{role}' lacks permission '{permission}'")


def enforce_four_eyes(*, author: str, approver: str, allow_self_approval: bool = False) -> None:
    if not allow_self_approval and author == approver:
        raise PolicyViolation("four-eyes rule: a change cannot be approved by its author")
