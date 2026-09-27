"""Request dependencies: authentication (users: JWT, nodes: API key) and RBAC."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from neurawall.core.errors import PolicyViolation
from neurawall.security.credentials import API_KEY_PREFIX, decode_token
from neurawall.security.rbac import Permission, Role, authorize
from neurawall.services.control_plane import db
from neurawall.services.control_plane.service import ControlPlane

_bearer = HTTPBearer(auto_error=False)


class Unauthenticated(PolicyViolation):
    code = "unauthenticated"


@dataclass(frozen=True)
class Principal:
    user_id: int
    email: str
    name: str
    role: Role
    must_change_password: bool


def get_cp(request: Request) -> ControlPlane:
    return request.app.state.cp  # type: ignore[no-any-return]


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                 cp: ControlPlane = Depends(get_cp)) -> Principal:
    if creds is None or creds.credentials.startswith(API_KEY_PREFIX):
        raise Unauthenticated("authentication required")
    try:
        claims = decode_token(creds.credentials, secret=cp.settings.jwt_secret)
        user = cp.get_user(int(claims["sub"]))
    except (PolicyViolation, ValueError, KeyError) as exc:
        raise Unauthenticated("invalid or expired session") from exc
    return Principal(user.id, user.email, user.name, Role(user.role), user.must_change_password)


def require(permission: Permission) -> Callable[[Principal], Principal]:
    def dep(user: Principal = Depends(current_user)) -> Principal:
        if user.must_change_password:
            raise PolicyViolation("password change required before continuing")
        authorize(user.role, permission)
        return user
    return dep


def current_node(creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
                 cp: ControlPlane = Depends(get_cp)) -> db.Node:
    if creds is None or not creds.credentials.startswith(API_KEY_PREFIX):
        raise Unauthenticated("node API key required")
    try:
        return cp.authenticate_node(creds.credentials)
    except PolicyViolation as exc:
        raise Unauthenticated(exc.message) from exc
