"""REST API v1. Every route is authenticated, RBAC-gated and input-validated."""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import func, or_, select

from neurawall import __version__
from neurawall.core.errors import NotFound, PolicyViolation
from neurawall.core.models import (
    Action,
    DraftSource,
    RuleDraft,
    RuleMatch,
    RuleMode,
    SignedEnvelope,
)
from neurawall.core.telemetry import REGISTRY
from neurawall.modules.flow_collector.ingest import parse_flows
from neurawall.security.rbac import Permission, Role, permissions_for
from neurawall.security.sso import verify_sso_token
from neurawall.services.control_plane import db
from neurawall.services.control_plane.api import serializers as ser
from neurawall.services.control_plane.api.deps import (
    Principal,
    Unauthenticated,
    current_node,
    current_user,
    get_cp,
    require,
)
from neurawall.services.control_plane.service import ControlPlane

CP = Annotated[ControlPlane, Depends(get_cp)]
Reader = Annotated[Principal, Depends(require(Permission.READ))]
Triager = Annotated[Principal, Depends(require(Permission.TRIAGE_ALERTS))]
AdvisorUser = Annotated[Principal, Depends(require(Permission.USE_ADVISOR))]
Author = Annotated[Principal, Depends(require(Permission.AUTHOR_RULES))]
Approver = Annotated[Principal, Depends(require(Permission.APPROVE_RULES))]
FleetAdmin = Annotated[Principal, Depends(require(Permission.MANAGE_FLEET))]
UserAdmin = Annotated[Principal, Depends(require(Permission.MANAGE_USERS))]
Auditor = Annotated[Principal, Depends(require(Permission.READ_AUDIT))]
NodeAuth = Annotated[db.Node, Depends(current_node)]


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- public / system

public = APIRouter(tags=["system"])


@public.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@public.get("/readyz")
def readyz(cp: CP) -> dict[str, Any]:
    return {"status": "ready", "bundle_version": cp.latest_version()}


@public.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    return REGISTRY.expose()


api = APIRouter(prefix="/api/v1")


@api.get("/version", tags=["system"])
def version() -> dict[str, str]:
    return {"version": __version__}


@api.get("/system", tags=["system"])
def system(cp: CP, _: Reader) -> dict[str, Any]:
    return cp.system_info()


@api.get("/pki/bundle-signing-key", tags=["system"])
def signing_key(cp: CP) -> dict[str, str]:
    kid, pem = cp.public_key()
    return {"key_id": kid, "public_key_pem": pem}


# ---------------------------------------------------------------- auth


class LoginIn(Body):
    email: Annotated[str, Field(max_length=254)]
    password: Annotated[str, Field(max_length=256)]


class SsoIn(Body):
    token: Annotated[str, Field(min_length=20, max_length=8192)]


class PasswordChangeIn(Body):
    current_password: Annotated[str, Field(max_length=256)]
    new_password: Annotated[str, Field(min_length=12, max_length=256)]


@api.post("/auth/login", tags=["auth"])
def login(body: LoginIn, request: Request, cp: CP) -> dict[str, Any]:
    limiter = request.app.state.login_limiter
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client) or not limiter.allow("user:" + body.email.lower()):
        raise PolicyViolation("too many login attempts; try again in a minute")
    token, user = cp.login(body.email, body.password)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": cp.settings.auth.access_token_ttl_seconds,
        "user": ser.user(user),
    }


@api.post("/auth/sso", tags=["auth"])
def login_sso(body: SsoIn, request: Request, cp: CP) -> dict[str, Any]:
    """Sign in from a Clerk session token. 404 unless `auth.sso_jwks_url` is set."""
    auth = cp.settings.auth
    if not auth.sso_jwks_url:
        raise NotFound("single sign-on is not enabled")
    limiter = request.app.state.login_limiter
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise PolicyViolation("too many login attempts; try again in a minute")
    identity = verify_sso_token(
        body.token,
        jwks_url=auth.sso_jwks_url,
        issuer=auth.sso_issuer,
        required_org_id=auth.sso_required_org_id,
    )
    token, user = cp.login_sso(identity.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": auth.access_token_ttl_seconds,
        "user": ser.user(user),
    }


@api.get("/auth/me", tags=["auth"])
def me(user: Annotated[Principal, Depends(current_user)]) -> dict[str, Any]:
    return {
        "id": user.user_id,
        "email": user.email,
        "name": user.name,
        "role": user.role.value,
        "must_change_password": user.must_change_password,
        "permissions": sorted(p.value for p in permissions_for(user.role)),
    }


@api.post("/auth/password", tags=["auth"])
def change_password(
    body: PasswordChangeIn, cp: CP, user: Annotated[Principal, Depends(current_user)]
) -> dict[str, str]:
    token = cp.change_password(user.user_id, body.current_password, body.new_password)
    return {"status": "changed", "access_token": token}


# ---------------------------------------------------------------- users


class UserIn(Body):
    email: EmailStr
    name: Annotated[str, Field(max_length=120)] = ""
    role: Role
    password: Annotated[str, Field(min_length=12, max_length=256)]


class UserPatch(Body):
    name: Annotated[str, Field(max_length=120)] | None = None
    role: Role | None = None
    active: bool | None = None


@api.get("/users", tags=["users"])
def list_users(cp: CP, _: UserAdmin) -> list[dict[str, Any]]:
    return [ser.user(u) for u in cp.list_users()]


@api.post("/users", tags=["users"], status_code=201)
def create_user(body: UserIn, cp: CP, actor: UserAdmin) -> dict[str, Any]:
    return ser.user(
        cp.create_user(
            actor.email, email=body.email, name=body.name, role=body.role, password=body.password
        )
    )


@api.patch("/users/{user_id}", tags=["users"])
def patch_user(user_id: int, body: UserPatch, cp: CP, actor: UserAdmin) -> dict[str, Any]:
    return ser.user(
        cp.update_user(actor.email, user_id, role=body.role, active=body.active, name=body.name)
    )


@api.post("/users/{user_id}/reset-password", tags=["users"])
def reset_password(user_id: int, cp: CP, actor: UserAdmin) -> dict[str, str]:
    return {"temporary_password": cp.reset_password(actor.email, user_id)}


# ---------------------------------------------------------------- dashboard


@api.get("/dashboard", tags=["dashboard"])
def dashboard(
    cp: CP, _: Reader, hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24
) -> dict[str, Any]:
    return cp.dashboard(hours)


# ---------------------------------------------------------------- flows


@api.get("/flows", tags=["flows"])
def list_flows(
    cp: CP,
    _: Reader,
    q: Annotated[str | None, Query(max_length=253)] = None,
    action: Annotated[str | None, Query(max_length=16)] = None,
    label: Annotated[str | None, Query(max_length=40)] = None,
    node: Annotated[str | None, Query(max_length=64)] = None,
    alert_id: int | None = None,
    min_score: Annotated[float | None, Query(ge=0, le=1)] = None,
    hours: Annotated[int, Query(ge=1, le=24 * 30)] = 24,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    stmt = select(db.FlowRow).where(db.FlowRow.ts >= time.time() - hours * 3600)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                db.FlowRow.src_ip == q,
                db.FlowRow.dst_ip == q,
                db.FlowRow.host.like(like),
                db.FlowRow.flow_id == q,
            )
        )
    if action == "blocked":
        stmt = stmt.where(db.FlowRow.enforced.is_(True))
    elif action:
        stmt = stmt.where(db.FlowRow.action == action)
    if label:
        stmt = stmt.where(db.FlowRow.labels.contains(label))
    if node:
        stmt = stmt.where(db.FlowRow.node_id == node)
    if alert_id is not None:
        stmt = stmt.where(db.FlowRow.alert_id == alert_id)
    if min_score is not None:
        stmt = stmt.where(db.FlowRow.anomaly_score >= min_score)
    with cp.db.session() as s:
        total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = s.scalars(stmt.order_by(db.FlowRow.ts.desc()).offset(offset).limit(limit)).all()
        return {"total": total, "items": [ser.flow_summary(r) for r in rows]}


@api.get("/flows/{flow_id}", tags=["flows"])
def get_flow(flow_id: str, cp: CP, _: Reader) -> dict[str, Any]:
    row, _ev, verdict = cp.get_flow(flow_id)
    return ser.flow_detail(row, verdict)


@api.post("/flows/{flow_id}/explain", tags=["flows", "advisor"])
def explain_flow(flow_id: str, cp: CP, _: AdvisorUser) -> dict[str, Any]:
    return cp.explain_flow(flow_id)


# ---------------------------------------------------------------- alerts


class AlertPatch(Body):
    status: Literal["open", "acknowledged", "resolved", "false_positive"] | None = None
    assignee: Annotated[str, Field(max_length=254)] | None = None


@api.get("/alerts", tags=["alerts"])
def list_alerts(
    cp: CP,
    _: Reader,
    status: str | None = None,
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    rows, total = cp.list_alerts(status=status, severity=severity, limit=limit, offset=offset)
    return {"total": total, "items": [ser.alert(a) for a in rows]}


@api.get("/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: int, cp: CP, _: Reader) -> dict[str, Any]:
    return ser.alert(cp.get_alert(alert_id))


@api.patch("/alerts/{alert_id}", tags=["alerts"])
def patch_alert(alert_id: int, body: AlertPatch, cp: CP, actor: Triager) -> dict[str, Any]:
    return ser.alert(
        cp.update_alert(actor.email, alert_id, status=body.status, assignee=body.assignee)
    )


@api.post("/alerts/{alert_id}/triage", tags=["alerts", "advisor"])
def triage_alert(alert_id: int, cp: CP, _: AdvisorUser) -> dict[str, Any]:
    return ser.alert(cp.triage_alert(alert_id, draft=True))


@api.post("/alerts/{alert_id}/narrate", tags=["alerts", "advisor"])
def narrate_alert(alert_id: int, cp: CP, actor: AdvisorUser) -> dict[str, Any]:
    return cp.narrate_alert(actor.email, alert_id)


# ---------------------------------------------------------------- rules


class RulePatch(Body):
    enabled: bool | None = None
    mode: RuleMode | None = None
    priority: Annotated[int, Field(ge=0, le=100000)] | None = None


@api.get("/rules", tags=["rules"])
def list_rules(cp: CP, _: Reader) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in cp.list_rules()]


@api.get("/rules/hygiene", tags=["rules", "advisor"])
def rule_hygiene(cp: CP, _: Reader) -> list[dict[str, Any]]:
    return cp.hygiene()


@api.get("/rules/{rule_id}", tags=["rules"])
def get_rule(rule_id: str, cp: CP, _: Reader) -> dict[str, Any]:
    return cp.get_rule(rule_id).model_dump(mode="json")


@api.patch("/rules/{rule_id}", tags=["rules"])
def patch_rule(rule_id: str, body: RulePatch, cp: CP, actor: Approver) -> dict[str, Any]:
    return cp.update_rule(
        actor.email, rule_id, enabled=body.enabled, mode=body.mode, priority=body.priority
    ).model_dump(mode="json")


@api.delete("/rules/{rule_id}", tags=["rules"], status_code=204)
def delete_rule(rule_id: str, cp: CP, actor: Approver) -> None:
    cp.delete_rule(actor.email, rule_id)


# ---------------------------------------------------------------- drafts


class DraftIn(Body):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    rationale: Annotated[str, Field(min_length=1, max_length=4000)]
    action: Action
    priority: Annotated[int, Field(ge=0, le=100000)] = 500
    match: RuleMatch


class SimulateIn(Body):
    action: Action
    match: RuleMatch


class ApproveIn(Body):
    mode: RuleMode = RuleMode.ALERT_ONLY
    note: Annotated[str, Field(max_length=2000)] = ""
    name: Annotated[str, Field(min_length=1, max_length=120)] | None = None
    priority: Annotated[int, Field(ge=0, le=100000)] | None = None
    acknowledge_blast_radius: bool = False


class RejectIn(Body):
    reason: Annotated[str, Field(min_length=1, max_length=2000)]


@api.get("/drafts", tags=["drafts"])
def list_drafts(cp: CP, _: Reader, status: str | None = None) -> list[dict[str, Any]]:
    return [ser.draft(d) for d in cp.list_drafts(status)]


@api.get("/drafts/{draft_id}", tags=["drafts"])
def get_draft(draft_id: str, cp: CP, _: Reader) -> dict[str, Any]:
    return ser.draft(cp.get_draft(draft_id))


@api.post("/drafts", tags=["drafts"], status_code=201)
def create_draft(body: DraftIn, cp: CP, actor: Author) -> dict[str, Any]:
    draft = RuleDraft(
        name=body.name,
        rationale=body.rationale,
        action=body.action,
        priority=body.priority,
        match=body.match,
        confidence=1.0,
        source=DraftSource.OPERATOR,
    )
    created = cp.create_draft(draft, actor=actor.email)
    return ser.draft(cp.get_draft(created.draft_id))


@api.post("/drafts/simulate", tags=["drafts"])
def simulate_draft(body: SimulateIn, cp: CP, _: Reader) -> dict[str, Any]:
    return cp.simulate(body.match, body.action).model_dump(mode="json")


@api.post("/drafts/{draft_id}/approve", tags=["drafts"])
def approve_draft(draft_id: str, body: ApproveIn, cp: CP, actor: Approver) -> dict[str, Any]:
    rule = cp.approve_draft(
        actor.email,
        draft_id,
        mode=body.mode,
        note=body.note,
        name=body.name,
        priority=body.priority,
        acknowledge_blast_radius=body.acknowledge_blast_radius,
    )
    return rule.model_dump(mode="json")


@api.post("/drafts/{draft_id}/reject", tags=["drafts"])
def reject_draft(draft_id: str, body: RejectIn, cp: CP, actor: Approver) -> dict[str, str]:
    cp.reject_draft(actor.email, draft_id, body.reason)
    return {"status": "rejected"}


# ---------------------------------------------------------------- bundles


class RollbackIn(Body):
    reason: Annotated[str, Field(min_length=1, max_length=500)]


@api.get("/bundles", tags=["bundles"])
def list_bundles(cp: CP, _: Reader) -> list[dict[str, Any]]:
    return [ser.bundle(b) for b in cp.list_bundles()]


@api.post("/bundles/publish", tags=["bundles"], status_code=201)
def publish(cp: CP, actor: Approver) -> dict[str, int]:
    return {"version": cp.publish_bundle(actor.email, note="manual publish")}


@api.post("/bundles/{version}/advance", tags=["bundles"])
def advance(version: int, cp: CP, actor: Approver) -> dict[str, Any]:
    return ser.bundle(cp.advance_rollout(actor.email, version))


@api.post("/bundles/{version}/rollback", tags=["bundles"])
def rollback(version: int, body: RollbackIn, cp: CP, actor: Approver) -> dict[str, Any]:
    return {
        "status": "rolled_back",
        "new_version": cp.rollback_bundle(actor.email, version, body.reason),
    }


# ---------------------------------------------------------------- fleet (operator side)


class EnrollmentTokenIn(Body):
    ttl_seconds: Annotated[int, Field(ge=60, le=7 * 86400)] = 3600
    #: >1 lets a fleet (e.g. a Kubernetes DaemonSet) enroll with one token.
    max_uses: Annotated[int, Field(ge=1, le=10000)] = 1


@api.get("/nodes", tags=["fleet"])
def list_nodes(cp: CP, _: Reader) -> list[dict[str, Any]]:
    latest = cp.latest_version()
    return [ser.node(n, latest) for n in cp.list_nodes()]


@api.post("/nodes/enrollment-tokens", tags=["fleet"], status_code=201)
def enrollment_token(body: EnrollmentTokenIn, cp: CP, actor: FleetAdmin) -> dict[str, Any]:
    return {
        "token": cp.create_enrollment_token(actor.email, body.ttl_seconds, body.max_uses),
        "expires_in": body.ttl_seconds,
        "max_uses": body.max_uses,
        "control_plane_url": cp.settings.public_url,
    }


@api.post("/nodes/{node_id}/revoke", tags=["fleet"])
def revoke_node(node_id: str, cp: CP, actor: FleetAdmin) -> dict[str, str]:
    cp.revoke_node(actor.email, node_id)
    return {"status": "revoked"}


# ---------------------------------------------------------------- audit


@api.get("/audit", tags=["audit"])
def list_audit(
    cp: CP,
    _: Auditor,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    action: Annotated[str | None, Query(max_length=100)] = None,
) -> dict[str, Any]:
    stmt = select(db.AuditRow)
    if action:
        stmt = stmt.where(db.AuditRow.action.startswith(action))
    with cp.db.session() as s:
        total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = s.scalars(stmt.order_by(db.AuditRow.seq.desc()).offset(offset).limit(limit)).all()
        return {"total": total, "items": [ser.audit(r) for r in rows]}


@api.get("/audit/verify", tags=["audit"])
def verify_audit(cp: CP, _: Auditor) -> dict[str, Any]:
    try:
        return {"valid": True, "entries": cp.verify_audit()}
    except Exception as exc:  # IntegrityFailure -> report, do not 500
        return {"valid": False, "error": str(exc)}


# ---------------------------------------------------------------- node agent endpoints

agent = APIRouter(prefix="/api/v1/agent", tags=["agent"])


class EnrollIn(Body):
    token: Annotated[str, Field(min_length=10, max_length=200)]
    name: Annotated[str, Field(min_length=1, max_length=120)]
    hostname: Annotated[str, Field(max_length=253)] = ""
    agent_version: Annotated[str, Field(max_length=40)] = ""
    backend: Annotated[str, Field(max_length=40)] = "dry-run"


class HeartbeatIn(Body):
    applied_version: Annotated[int, Field(ge=0)]
    backend: Annotated[str, Field(max_length=40)]
    stats: dict[str, Any] = {}


class FlowBatchIn(Body):
    applied_version: Annotated[int, Field(ge=0)] | None = None
    flows: Annotated[list[dict[str, Any]], Field(max_length=5000)]


@agent.post("/enroll", status_code=201)
def enroll(body: EnrollIn, cp: CP) -> dict[str, Any]:
    node, api_key = cp.enroll_node(
        body.token,
        name=body.name,
        hostname=body.hostname,
        agent_version=body.agent_version,
        backend=body.backend,
    )
    kid, pem = cp.public_key()
    return {
        "node_id": node.id,
        "api_key": api_key,
        "signing_key_id": kid,
        "signing_public_key": pem,
    }


@agent.post("/heartbeat")
def heartbeat(body: HeartbeatIn, cp: CP, node: NodeAuth) -> dict[str, Any]:
    cp.heartbeat(
        node.id, applied_version=body.applied_version, backend=body.backend, stats=body.stats
    )
    return {"latest_version": cp.bundle_for_node(node.id).payload.get("version")}


@agent.get("/bundle")
def get_bundle(cp: CP, node: NodeAuth) -> dict[str, Any]:
    env: SignedEnvelope = cp.bundle_for_node(node.id)
    return env.model_dump(mode="json")


@agent.post("/flows")
def ingest_flows(body: FlowBatchIn, cp: CP, node: NodeAuth) -> dict[str, Any]:
    parsed = parse_flows(body.flows, node_id=node.id)
    outcome = cp.ingest(node.id, parsed.flows, node_version=body.applied_version or None)
    by_id = {f.flow_id: f for f in parsed.flows}
    return {
        "accepted": outcome.accepted,
        "rejected": parsed.rejected,
        "errors": parsed.errors,
        "bundle_version": outcome.bundle_version,
        "verdicts": [
            {
                "flow": by_id[v.flow_id].model_dump(
                    mode="json", include={"flow_id", "src_ip", "dst_ip", "dst_port", "protocol"}
                ),
                "verdict": v.model_dump(mode="json"),
            }
            for v in outcome.verdicts
            if v.flow_id in by_id
        ],
    }


# ---------------------------------------------------------------- billing

BillingAdmin = Annotated[Principal, Depends(require(Permission.MANAGE_SETTINGS))]


class CheckoutIn(Body):
    plan: Literal["pro", "business", "enterprise"]
    interval: Literal["month", "year"] = "month"


@api.get("/billing", tags=["billing"])
def billing_status(cp: CP, _: Reader) -> dict[str, Any]:
    return cp.billing_status()


@api.get("/billing/plans", tags=["billing"])
def billing_plans(cp: CP) -> list[dict[str, Any]]:
    """Public: the plan catalogue (no account, no secrets)."""
    return cp.billing_status()["plans"]


@api.post("/billing/checkout", tags=["billing"])
def billing_checkout(body: CheckoutIn, cp: CP, actor: BillingAdmin) -> dict[str, str]:
    return {
        "checkout_url": cp.start_checkout(actor.email, plan_id=body.plan, interval=body.interval)
    }


@api.post("/billing/portal", tags=["billing"])
def billing_portal(cp: CP, actor: BillingAdmin) -> dict[str, str]:
    return {"portal_url": cp.start_portal(actor.email)}


@api.post("/billing/webhook", tags=["billing"])
async def billing_webhook(request: Request, cp: CP) -> dict[str, str]:
    """Public: Stripe authenticates itself with the `Stripe-Signature` HMAC over the exact
    raw body. Foreign or unknown events return 200 "ignored" so Stripe never disables
    the shared endpoint."""
    raw = await request.body()
    try:
        status = cp.apply_stripe_webhook(raw, request.headers.get("Stripe-Signature", ""))
    except PolicyViolation as exc:
        raise Unauthenticated(exc.message) from exc
    return {"status": status}
