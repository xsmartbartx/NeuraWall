"""Control-plane core: every workflow, independent of HTTP.

* Ingest: Tier 1 -> Tier 2 -> policy engine for each flow, persisted with signals.
* Alerts: grouped by (source, rule/label) in a 30-minute window; Tier 3 triage queued.
* Rule lifecycle: draft -> simulate -> human approval -> signed bundle -> staged rollout.
* Audit: every enforcement change and approval, hash-chained.
"""

from __future__ import annotations

import queue
import random
import secrets
import socket
import threading
import time
import uuid
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from neurawall import __version__
from neurawall.core.config import Settings
from neurawall.core.errors import NotFound, PolicyViolation, ValidationFailure
from neurawall.core.logging import get_logger
from neurawall.core.models import (
    Action,
    AnomalyScore,
    Classification,
    DraftSource,
    Evidence,
    FlowRecord,
    PolicyBundle,
    Rule,
    RuleDraft,
    RuleMatch,
    RuleMode,
    SignedEnvelope,
    SimulationResult,
    Verdict,
)
from neurawall.core.telemetry import REGISTRY
from neurawall.modules.anomaly_engine import AnomalyEngine
from neurawall.modules.billing import (
    PLANS,
    NotOurEvent,
    Plan,
    StripeClient,
    check_nodes,
    entitlements,
    interpret_event,
    parse_event,
    verify_signature,
)
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.l7_classifier import L7Classifier, needs_tier3
from neurawall.modules.llm_advisor import CallRecord, ClaudeBackend, LlmAdvisor
from neurawall.modules.llm_advisor.advisor import Backend
from neurawall.modules.nexora import NexoraClient, NexoraError
from neurawall.modules.notify import WebhookError, check_url, derive_secret, send_webhook
from neurawall.modules.policy_engine import (
    PolicyEngine,
    RolloutState,
    analyze_hygiene,
    should_rollback,
    sign_bundle,
    simulate,
)
from neurawall.security.audit import AuditEntry, build_entry, verify_chain
from neurawall.security.credentials import (
    api_key_matches,
    generate_api_key,
    hash_api_key,
    hash_password,
    issue_token,
    verify_password,
)
from neurawall.security.integrity import FileSigner, Signer
from neurawall.security.rbac import Role, enforce_four_eyes
from neurawall.security.sso import SsoIdentity
from neurawall.services.control_plane import db
from neurawall.services.control_plane.starter import starter_rules

log = get_logger(__name__)

ALERT_WINDOW_SECONDS = 1800
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SYSTEM_ACTOR = "system"
ADVISOR_ACTOR = "tier3-advisor"

_ingested = REGISTRY.counter("neurawall_flows_ingested_total", "Flows ingested by node")
_alerts_created = REGISTRY.counter("neurawall_alerts_created_total", "Alerts created")


@dataclass
class IngestOutcome:
    accepted: int
    verdicts: list[Verdict]
    bundle_version: int


def _severity_for(ev: Evidence, verdict: Verdict) -> str:
    from neurawall.modules.llm_advisor.heuristic import summarize

    sev = summarize([ev]).severity
    if verdict.enforced and SEVERITY_ORDER[sev] < 2:
        sev = "high"
    return sev


class ControlPlane:
    def __init__(
        self,
        settings: Settings,
        *,
        signer: Signer | None = None,
        advisor_backend: Backend | str | None = "auto",
    ) -> None:
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        settings.data_dir.chmod(0o700)  # database, signing key and bootstrap secret live here
        self.db = db.Database(settings.resolved_database_url)
        self.signer = signer or FileSigner(settings.data_dir / "keys" / "bundle-signing.pem")
        self.anomaly = AnomalyEngine(
            warmup_flows=settings.inference.baseline_warmup_flows,
            trees=settings.inference.isolation_forest_trees,
        )
        self.classifier = L7Classifier(rate_per_second=settings.inference.t2_rate_per_second)
        self.advisor = LlmAdvisor(
            self._make_backend(advisor_backend),
            max_calls_per_hour=settings.llm.max_calls_per_hour,
            allowed=lambda: self.plan().llm_advisor_allowed,
            within_budget=self._llm_within_budget,
            on_call=self._record_llm_call,
        )
        self._engines: dict[int, PolicyEngine] = {}
        self._nexora_lock = threading.Lock()
        self._notify_queue: deque[tuple[str, str, float, dict[str, Any]]] = deque(maxlen=5_000)
        self._test_sends: list[float] = []
        self._notify_transport: httpx.BaseTransport | None = None  # tests inject a fake receiver
        self._resolver: Any = None  # tests inject a fake DNS; None = the system resolver
        self._events: deque[tuple[str, float, dict[str, Any]]] = deque(maxlen=10_000)
        self._flows_since_rollup = 0
        self._last_rollup = time.time()
        self._manual_syncs: list[float] = []
        self._nexora_transport: httpx.BaseTransport | None = None  # tests inject a fake NEXORA
        self._audit_lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._ingest_lock = threading.Lock()
        self._tier3: queue.Queue[int] = queue.Queue(maxsize=500)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.started_at = time.time()
        self._bootstrap()

    # ------------------------------------------------------------------ setup

    def _make_backend(self, spec: Backend | str | None) -> Backend | None:
        if spec != "auto":
            return spec  # type: ignore[return-value]
        llm = self.settings.llm
        if llm.provider != "anthropic":
            return None
        key = self.settings.anthropic_api_key
        if not key:
            log.warning(
                "no Anthropic API key configured; Tier 3 runs the offline heuristic advisor"
            )
            return None
        return ClaudeBackend(
            api_key=key,
            model=llm.model,
            max_tokens=llm.max_tokens,
            effort=llm.effort,
            timeout_seconds=llm.timeout_seconds,
            server_side_fallbacks=llm.server_side_fallbacks,
            workspace_id=self.settings.anthropic_workspace_id,
        )

    def _bootstrap(self) -> None:
        with self.db.session() as s:
            if s.get(db.Setting, "installation_id") is None:
                # Identifies this control plane's subscriptions on a shared Stripe account.
                s.add(db.Setting(key="installation_id", value="nwi_" + secrets.token_hex(12)))
            if s.scalar(select(func.count()).select_from(db.User)) == 0:
                self._create_bootstrap_admin(s)
            has_bundle = (s.scalar(select(func.count()).select_from(db.BundleRow)) or 0) > 0
            if not has_bundle and self.settings.policy.starter_rules:
                for rule in starter_rules():
                    s.add(db.RuleRow(id=rule.id, data=rule.model_dump(mode="json")))
        if not has_bundle:
            self.publish_bundle(SYSTEM_ACTOR, note="initial bundle", immediate=True)
            return
        with self.db.session() as s:
            latest = s.scalars(
                select(db.BundleRow).order_by(db.BundleRow.version.desc()).limit(1)
            ).first()
            signed_by = latest.envelope.get("key_id") if latest else None
        if signed_by != self.signer.key_id:
            # Signing key rotated: re-sign the current rule set so re-enrolled nodes accept it.
            log.warning(
                "bundle-signing key changed; publishing a re-signed bundle",
                previous_key=signed_by,
                current_key=self.signer.key_id,
            )
            self.publish_bundle(SYSTEM_ACTOR, note="re-signed after key rotation", immediate=True)

    def _create_bootstrap_admin(self, s: Session) -> None:
        cfg = self.settings.auth
        if cfg.bootstrap_admin_password is not None:
            password = cfg.bootstrap_admin_password.get_secret_value()
            must_change = False
        else:
            password = secrets.token_urlsafe(12) + "A1!"
            must_change = True
            path = self.settings.data_dir / "initial-admin-password.txt"
            path.touch(mode=0o600)
            path.write_text(f"{cfg.bootstrap_admin_email}\n{password}\n")
            log.warning(
                "bootstrap admin created; initial password written to file",
                email=cfg.bootstrap_admin_email,
                path=str(path),
            )
        s.add(
            db.User(
                email=cfg.bootstrap_admin_email.lower(),
                name="Administrator",
                role=Role.ADMIN.value,
                password_hash=hash_password(password),
                must_change_password=must_change,
            )
        )

    def start_background(self) -> None:
        self._threads = [
            threading.Thread(target=self._tier3_worker, name="tier3-worker", daemon=True),
            threading.Thread(target=self._maintenance_loop, name="maintenance", daemon=True),
        ]
        if self.settings.demo_mode:
            self._threads.append(threading.Thread(target=self._demo_loop, name="demo", daemon=True))
        self._threads.append(threading.Thread(target=self._notify_loop, name="notify", daemon=True))
        if self.linked:
            self._threads.append(
                threading.Thread(target=self._nexora_loop, name="nexora-sync", daemon=True)
            )
            if self.settings.nexora.events_enabled:
                self._threads.append(
                    threading.Thread(target=self._outbox_loop, name="outbox", daemon=True)
                )
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self.db.engine.dispose()

    # ------------------------------------------------------------------ audit

    def audit(
        self, actor: str, action: str, target: str, detail: dict[str, Any] | None = None
    ) -> None:
        with self._audit_lock, self.db.session() as s:
            last = s.scalars(select(db.AuditRow).order_by(db.AuditRow.seq.desc()).limit(1)).first()
            prev = AuditEntry.model_validate(last, from_attributes=True) if last else None
            e = build_entry(
                prev=prev, ts=time.time(), actor=actor, action=action, target=target, detail=detail
            )
            s.add(db.AuditRow(**e.model_dump()))
        self._emit_for_audit(action, target, detail or {})
        if action == "draft.create" and target.startswith("draft:"):
            self._notify("draft.pending", target[6:], {"draft_id": target[6:], "by": actor})

    #: Audit actions that are also usage events, and the only fields that leave the host.
    _EVENT_FOR_AUDIT: dict[str, tuple[str, tuple[str, ...]]] = {
        "node.enroll": ("neurawall.node.enrolled", ()),
        "node.revoke": ("neurawall.node.revoked", ()),
        "draft.approve": ("neurawall.rule.approved", ("mode",)),
        "bundle.publish": ("neurawall.bundle.published", ("rules",)),
        "bundle.rollback": ("neurawall.bundle.rolled_back", ()),
    }

    def _emit_for_audit(self, action: str, target: str, detail: dict[str, Any]) -> None:
        spec = self._EVENT_FOR_AUDIT.get(action)
        if spec is None:
            return
        event_type, fields = spec
        data = {k: detail[k] for k in fields if isinstance(detail.get(k), str | int)}
        if action.startswith("bundle.") and target.startswith("bundle:v"):
            data["version"] = int(target[8:]) if target[8:].isdigit() else 0
        self._emit(event_type, data)

    def verify_audit(self) -> int:
        with self.db.session() as s:
            rows = s.scalars(select(db.AuditRow).order_by(db.AuditRow.seq)).all()
            return verify_chain([AuditEntry.model_validate(r, from_attributes=True) for r in rows])

    # ------------------------------------------------------------------ users & auth

    def login(self, email: str, password: str) -> tuple[str, db.User]:
        with self.db.session() as s:
            user = s.scalars(select(db.User).where(db.User.email == email.lower().strip())).first()
            if user is None:
                # Constant-ish work either way to limit user enumeration by timing.
                verify_password(password, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA")
                raise PolicyViolation("invalid email or password")
            # `admin_only` keeps password sign-in for break-glass admins. It is the same error,
            # so a refusal does not reveal which rule applied.
            allowed = self.settings.auth.local_login == "enabled" or user.role == Role.ADMIN.value
            if not (user.active and verify_password(password, user.password_hash) and allowed):
                raise PolicyViolation("invalid email or password")
            user.last_login = time.time()
            token = issue_token(
                subject=str(user.id),
                role=user.role,
                secret=self.settings.jwt_secret,
                ttl_seconds=self.settings.auth.access_token_ttl_seconds,
            )
            s.flush()  # expunge() would drop the pending last_login update
            s.expunge(user)
        self.audit(user.email, "auth.login", f"user:{user.id}")
        return token, user

    def login_sso(self, identity: SsoIdentity) -> tuple[str, db.User]:
        """Sign in from a verified identity-provider token.

        Match order: the provider's user id, then (once) an existing user with the same email,
        which is linked to that id. With `auth.sso_jit` an unknown member of the required
        organisation gets a `viewer`. A role is never taken from the token."""
        auth = self.settings.auth
        denied = PolicyViolation("single sign-on was not accepted")
        provisioned = False
        with self.db.session() as s:
            user = s.scalars(select(db.User).where(db.User.external_id == identity.subject)).first()
            if user is None:
                user = s.scalars(select(db.User).where(db.User.email == identity.email)).first()
                if user is not None:
                    if user.external_id is not None:
                        raise denied  # that email belongs to a different provider identity
                    user.external_id = identity.subject
                elif auth.sso_jit and identity.email_verified and identity.org_id:
                    user = db.User(
                        email=identity.email,
                        name=identity.name or identity.email.split("@")[0],
                        role=Role.VIEWER.value,
                        # Nobody knows this password: it is random and never shown.
                        password_hash=hash_password(secrets.token_urlsafe(48) + "aA1!"),
                        external_id=identity.subject,
                        auth_provider="nexora",
                    )
                    s.add(user)
                    try:
                        s.flush()
                    except IntegrityError:
                        # A second sign-in for the same identity won the race; they retry.
                        raise denied from None
                    provisioned = True
                else:
                    raise denied
            if not user.active:
                raise denied
            user.last_login = time.time()
            token = issue_token(
                subject=str(user.id),
                role=user.role,
                secret=self.settings.jwt_secret,
                ttl_seconds=auth.sso_ttl_seconds,
            )
            s.flush()  # expunge() would drop the pending last_login / external_id update
            s.expunge(user)
        if provisioned:
            self.audit(user.email, "auth.sso.provision", f"user:{user.id}", {"role": user.role})
        self.audit(user.email, "auth.login.sso", f"user:{user.id}")
        return token, user

    DEMO_EMAIL = "demo@neurawall.local"
    DEMO_SESSION_SECONDS = 1800

    def login_demo(self) -> tuple[str, db.User]:
        """A read-only viewer session on a demo instance (see `auth.demo_public_login`)."""
        if not (self.settings.auth.demo_public_login and self.settings.demo_mode):
            raise NotFound("the public demo is not enabled")
        with self.db.session() as s:
            user = s.scalars(select(db.User).where(db.User.email == self.DEMO_EMAIL)).first()
            if user is None:
                user = db.User(
                    email=self.DEMO_EMAIL,
                    name="Demo visitor",
                    role=Role.VIEWER.value,
                    password_hash=hash_password(secrets.token_urlsafe(48) + "aA1!"),
                )
                s.add(user)
                s.flush()
            if user.role != Role.VIEWER.value or not user.active:
                # An administrator changed the demo account: never hand out a session for it.
                raise NotFound("the public demo is not enabled")
            token = issue_token(
                subject=str(user.id),
                role=user.role,
                secret=self.settings.jwt_secret,
                ttl_seconds=self.DEMO_SESSION_SECONDS,
            )
            s.expunge(user)
        return token, user

    def get_user(self, user_id: int) -> db.User:
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None or not u.active:
                raise NotFound("user not found")
            s.expunge(u)
            return u

    def list_users(self) -> list[db.User]:
        with self.db.session() as s:
            users = list(s.scalars(select(db.User).order_by(db.User.id)).all())
            for u in users:
                s.expunge(u)
            return users

    def create_user(
        self, actor: str, *, email: str, name: str, role: Role, password: str
    ) -> db.User:
        with self.db.session() as s:
            if s.scalars(select(db.User).where(db.User.email == email.lower())).first():
                raise ValidationFailure("a user with this email already exists")
            u = db.User(
                email=email.lower(),
                name=name,
                role=role.value,
                password_hash=hash_password(password),
                must_change_password=True,
            )
            s.add(u)
            s.flush()
            s.expunge(u)
        self.audit(actor, "user.create", f"user:{u.id}", {"email": u.email, "role": role.value})
        return u

    def update_user(
        self,
        actor: str,
        user_id: int,
        *,
        role: Role | None = None,
        active: bool | None = None,
        name: str | None = None,
    ) -> db.User:
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None:
                raise NotFound("user not found")
            if (
                (role is not None and role != Role.ADMIN) or active is False
            ) and u.role == Role.ADMIN:
                admins = s.scalar(
                    select(func.count())
                    .select_from(db.User)
                    .where(db.User.role == Role.ADMIN.value, db.User.active.is_(True))
                )
                if (admins or 0) <= 1:
                    raise PolicyViolation("cannot demote or deactivate the last active admin")
            if role is not None:
                u.role = role.value
            if active is not None:
                u.active = active
                if not active:
                    u.sessions_valid_after = time.time()
            if name is not None:
                u.name = name
            s.flush()
            s.expunge(u)
        self.audit(
            actor,
            "user.update",
            f"user:{user_id}",
            {"role": role.value if role else None, "active": active},
        )
        return u

    def issue_session(self, user: db.User) -> str:
        return issue_token(
            subject=str(user.id),
            role=user.role,
            secret=self.settings.jwt_secret,
            ttl_seconds=self.settings.auth.access_token_ttl_seconds,
        )

    def change_password(self, user_id: int, current: str, new: str) -> str:
        """Change the password, revoke every existing session and return a fresh one."""
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None or not verify_password(current, u.password_hash):
                raise PolicyViolation("current password is incorrect")
            u.password_hash = hash_password(new)
            u.must_change_password = False
            u.sessions_valid_after = time.time()
            email = u.email
        bootstrap_file = self.settings.data_dir / "initial-admin-password.txt"
        if email == self.settings.auth.bootstrap_admin_email.lower() and bootstrap_file.exists():
            bootstrap_file.unlink()
        self.audit(email, "user.password_change", f"user:{user_id}")
        return self.issue_session(self.get_user(user_id))

    def reset_password(self, actor: str, user_id: int) -> str:
        temp = secrets.token_urlsafe(12) + "A1!"
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None:
                raise NotFound("user not found")
            if u.auth_provider != "local":
                raise ValidationFailure("this account signs in with NEXORA and has no password")
            u.password_hash = hash_password(temp)
            u.must_change_password = True
            u.sessions_valid_after = time.time()
        self.audit(actor, "user.password_reset", f"user:{user_id}")
        return temp

    # ------------------------------------------------------------------ nodes

    def create_enrollment_token(
        self, actor: str, ttl_seconds: int = 3600, max_uses: int = 1
    ) -> str:
        token = "nwe_" + secrets.token_urlsafe(24)
        with self.db.session() as s:
            s.add(
                db.EnrollmentToken(
                    token_hash=hash_api_key(token),
                    created_by=actor,
                    expires_at=time.time() + ttl_seconds,
                    uses_remaining=max_uses,
                )
            )
        self.audit(
            actor,
            "node.enrollment_token",
            "fleet",
            {"ttl_seconds": ttl_seconds, "max_uses": max_uses},
        )
        return token

    def enroll_node(
        self, token: str, *, name: str, hostname: str, agent_version: str, backend: str
    ) -> tuple[db.Node, str]:
        with self.db.session() as s:
            row = s.scalars(
                select(db.EnrollmentToken).where(
                    db.EnrollmentToken.token_hash == hash_api_key(token)
                )
            ).first()
            if row is None or row.uses_remaining <= 0 or row.expires_at < time.time():
                raise PolicyViolation("enrollment token is invalid, used or expired")
            active_nodes = (
                s.scalar(
                    select(func.count()).select_from(db.Node).where(db.Node.revoked.is_(False))
                )
                or 0
            )
            decision = check_nodes(active_nodes, self.plan())
            if not decision.allowed:
                raise PolicyViolation(decision.reason)
            api_key, key_hash = generate_api_key()
            node = db.Node(
                id="node-" + secrets.token_hex(6),
                name=name[:120],
                hostname=hostname[:253],
                api_key_hash=key_hash,
                agent_version=agent_version[:40],
                backend=backend[:40],
            )
            s.add(node)
            row.uses_remaining -= 1
            row.used_by_node = node.id
            s.flush()
            s.expunge(node)
        self.audit("enrollment", "node.enroll", node.id, {"name": name, "hostname": hostname})
        return node, api_key

    def authenticate_node(self, api_key: str) -> db.Node:
        with self.db.session() as s:
            node = s.scalars(
                select(db.Node).where(db.Node.api_key_hash == hash_api_key(api_key))
            ).first()
            if node is None or node.revoked or not api_key_matches(api_key, node.api_key_hash):
                raise PolicyViolation("unknown or revoked node credentials")
            node.last_seen = time.time()
            s.expunge(node)
            return node

    def heartbeat(
        self, node_id: str, *, applied_version: int, backend: str, stats: dict[str, Any]
    ) -> None:
        with self.db.session() as s:
            node = s.get(db.Node, node_id)
            if node is None:
                raise NotFound("node not found")
            if node.applied_version != applied_version:
                self.audit(node_id, "node.bundle_applied", node_id, {"version": applied_version})
            node.applied_version = applied_version
            node.backend = backend[:40]
            node.last_seen = time.time()
            node.stats = {k: stats[k] for k in list(stats)[:20]}
            s.add(
                db.NodeHeartbeat(
                    node_id=node_id,
                    applied_version=applied_version,
                    blocked=int(stats.get("active_blocks", 0) or 0),
                    flows=int(stats.get("flows_sent", 0) or 0),
                )
            )

    def list_nodes(self) -> list[db.Node]:
        with self.db.session() as s:
            nodes = list(s.scalars(select(db.Node).order_by(db.Node.enrolled_at)).all())
            for n in nodes:
                s.expunge(n)
            return nodes

    def revoke_node(self, actor: str, node_id: str) -> None:
        with self.db.session() as s:
            node = s.get(db.Node, node_id)
            if node is None:
                raise NotFound("node not found")
            node.revoked = True
        self.audit(actor, "node.revoke", node_id)

    # ------------------------------------------------------------------ rules & bundles

    def list_rules(self, include_deleted: bool = False) -> list[Rule]:
        with self.db.session() as s:
            q = select(db.RuleRow)
            if not include_deleted:
                q = q.where(db.RuleRow.deleted.is_(False))
            return sorted(
                (Rule.model_validate(r.data) for r in s.scalars(q)),
                key=lambda r: (r.priority, r.id),
            )

    def get_rule(self, rule_id: str) -> Rule:
        with self.db.session() as s:
            row = s.get(db.RuleRow, rule_id)
            if row is None or row.deleted:
                raise NotFound(f"rule {rule_id} not found")
            return Rule.model_validate(row.data)

    def _next_rule_id(self, s: Session) -> str:
        ids = s.scalars(select(db.RuleRow.id)).all()
        n = max((int(i.split("-")[1]) for i in ids), default=0) + 1
        return f"R-{n:06d}"

    def update_rule(
        self,
        actor: str,
        rule_id: str,
        *,
        enabled: bool | None = None,
        mode: RuleMode | None = None,
        priority: int | None = None,
    ) -> Rule:
        with self.db.session() as s:
            row = s.get(db.RuleRow, rule_id)
            if row is None or row.deleted:
                raise NotFound(f"rule {rule_id} not found")
            rule = Rule.model_validate(row.data)
            changes: dict[str, Any] = {}
            if enabled is not None:
                changes["enabled"] = enabled
            if mode is not None:
                changes["mode"] = mode
            if priority is not None:
                changes["priority"] = priority
            if not changes:
                return rule
            rule = rule.model_copy(
                update={**changes, "version": rule.version + 1, "approved_by": actor}
            )
            Rule.model_validate(rule.model_dump())  # re-validate after copy
            row.data = rule.model_dump(mode="json")
            row.updated_at = time.time()
        self.audit(actor, "rule.update", rule_id, {k: str(v) for k, v in changes.items()})
        self.publish_bundle(actor, note=f"{rule_id} updated")
        return rule

    def delete_rule(self, actor: str, rule_id: str) -> None:
        with self.db.session() as s:
            row = s.get(db.RuleRow, rule_id)
            if row is None or row.deleted:
                raise NotFound(f"rule {rule_id} not found")
            row.deleted = True
        self.audit(actor, "rule.delete", rule_id)
        self.publish_bundle(actor, note=f"{rule_id} deleted")

    def publish_bundle(self, actor: str, *, note: str = "", immediate: bool = False) -> int:
        with self._publish_lock, self.db.session() as s:
            version = (s.scalar(select(func.max(db.BundleRow.version))) or 0) + 1
            rules = [
                Rule.model_validate(r.data)
                for r in s.scalars(select(db.RuleRow).where(db.RuleRow.deleted.is_(False)))
            ]
            bundle = PolicyBundle(version=version, rules=rules)
            env = sign_bundle(bundle, self.signer)
            s.execute(
                update(db.BundleRow)
                .where(db.BundleRow.status == "rolling_out")
                .values(status="superseded")
            )
            final_stage = len(RolloutState(version, 0).stages) - 1
            s.add(
                db.BundleRow(
                    version=version,
                    created_by=actor,
                    envelope=env.model_dump(mode="json"),
                    rule_count=len(rules),
                    note=note[:500],
                    stage_index=final_stage if immediate or version == 1 else 0,
                    status="active" if immediate or version == 1 else "rolling_out",
                )
            )
            self._engines[version] = PolicyEngine(bundle)
        self.audit(
            actor,
            "bundle.publish",
            f"bundle:v{version}",
            {"rules": len(rules), "note": note, "signing_key": self.signer.key_id},
        )
        return version

    def latest_version(self) -> int:
        with self.db.session() as s:
            return s.scalar(select(func.max(db.BundleRow.version))) or 0

    def engine_for(self, version: int | None = None) -> PolicyEngine:
        if version and version in self._engines:
            return self._engines[version]
        with self.db.session() as s:
            q = select(db.BundleRow).where(db.BundleRow.status != "rolled_back")
            q = (
                q.where(db.BundleRow.version == version)
                if version
                else q.order_by(db.BundleRow.version.desc())
            )
            row = s.scalars(q.limit(1)).first()
            if row is None:
                return (
                    self.engine_for(None)
                    if version
                    else PolicyEngine(PolicyBundle(version=1, rules=[]))
                )
            env = SignedEnvelope.model_validate(row.envelope)
        engine = PolicyEngine(PolicyBundle.model_validate(env.payload))
        self._engines[engine.version] = engine
        return engine

    def bundle_for_node(self, node_id: str) -> SignedEnvelope:
        """Newest bundle whose rollout stage includes this node (canary 5% -> 25% -> 100%)."""
        with self.db.session() as s:
            rows = s.scalars(
                select(db.BundleRow)
                .where(db.BundleRow.status != "rolled_back")
                .order_by(db.BundleRow.version.desc())
                .limit(20)
            ).all()
            for row in rows:
                st = RolloutState(row.version, row.stage_index)
                if row.status == "active" or st.complete or st.includes(node_id):
                    return SignedEnvelope.model_validate(row.envelope)
        raise NotFound("no policy bundle available")

    def list_bundles(self, limit: int = 50) -> list[db.BundleRow]:
        with self.db.session() as s:
            rows = list(
                s.scalars(
                    select(db.BundleRow).order_by(db.BundleRow.version.desc()).limit(limit)
                ).all()
            )
            for r in rows:
                s.expunge(r)
            return rows

    def advance_rollout(self, actor: str, version: int) -> db.BundleRow:
        with self.db.session() as s:
            row = s.get(db.BundleRow, version)
            if row is None or row.status != "rolling_out":
                raise PolicyViolation("bundle is not rolling out")
            st = RolloutState(row.version, row.stage_index).advance()
            row.stage_index = st.stage_index
            if st.complete:
                row.status = "active"
                s.execute(
                    update(db.BundleRow)
                    .where(db.BundleRow.version < version, db.BundleRow.status == "active")
                    .values(status="superseded")
                )
            s.flush()
            s.expunge(row)
        self.audit(actor, "bundle.rollout_advance", f"bundle:v{version}", {"percent": st.percent})
        return row

    def rollback_bundle(self, actor: str, version: int, reason: str) -> int:
        """Restore the rule set of the newest earlier good bundle and publish it as a *new*
        version, so nodes' anti-rollback (monotonic versions) accepts it."""
        with self.db.session() as s:
            row = s.get(db.BundleRow, version)
            if row is None:
                raise NotFound("bundle not found")
            if row.status == "rolled_back":
                raise PolicyViolation("bundle is already rolled back")
            prev = s.scalars(
                select(db.BundleRow)
                .where(db.BundleRow.version < version, db.BundleRow.status != "rolled_back")
                .order_by(db.BundleRow.version.desc())
                .limit(1)
            ).first()
            if prev is None:
                raise PolicyViolation("no earlier bundle to roll back to")
            row.status = "rolled_back"
            restored = [Rule.model_validate(r) for r in prev.envelope["payload"]["rules"]]
            keep = {r.id for r in restored}
            for rr in s.scalars(select(db.RuleRow)):
                rr.deleted = rr.id not in keep
            for rule in restored:
                existing = s.get(db.RuleRow, rule.id)
                if existing is None:
                    s.add(db.RuleRow(id=rule.id, data=rule.model_dump(mode="json")))
                else:
                    existing.data, existing.deleted = rule.model_dump(mode="json"), False
            prev_version = prev.version
        self.audit(
            actor,
            "bundle.rollback",
            f"bundle:v{version}",
            {"reason": reason, "restored_from": prev_version},
        )
        return self.publish_bundle(
            actor, note=f"rollback of v{version} to rules of v{prev_version}", immediate=True
        )

    def public_key(self) -> tuple[str, str]:
        return self.signer.key_id, self.signer.public_key_pem()

    # ------------------------------------------------------------------ ingest pipeline

    def ingest(
        self, node_id: str, flows: list[FlowRecord], *, node_version: int | None = None
    ) -> IngestOutcome:
        if not flows:
            return IngestOutcome(0, [], self.latest_version())
        cfg = self.settings.inference
        engine = self.engine_for(node_version)
        with self._ingest_lock:
            anomalies = self.anomaly.score_batch(flows)
            results: list[tuple[Evidence, Verdict]] = []
            for flow, anomaly in zip(flows, anomalies, strict=True):
                cls: list[Classification] = []
                if self.classifier.should_invoke(flow, anomaly, cfg.t2_escalation_threshold):
                    cls = self.classifier.classify(flow, anomaly)
                ev = Evidence(flow=flow, anomaly=anomaly, classifications=tuple(cls))
                results.append((ev, engine.evaluate(ev)))
        self._persist(node_id, results)
        _ingested.inc(len(flows), node=node_id)
        self._flows_since_rollup += len(flows)
        blocking = [v for _, v in results if v.enforced]
        return IngestOutcome(len(flows), blocking, engine.version)

    def _persist(self, node_id: str, results: list[tuple[Evidence, Verdict]]) -> None:
        tier3: list[int] = []
        with self.db.session() as s:
            existing = set(
                s.scalars(
                    select(db.FlowRow.flow_id).where(
                        db.FlowRow.flow_id.in_([ev.flow.flow_id for ev, _ in results])
                    )
                ).all()
            )
            for ev, v in results:
                f = ev.flow
                if f.flow_id in existing:
                    continue
                existing.add(f.flow_id)
                row = db.FlowRow(
                    flow_id=f.flow_id,
                    node_id=node_id,
                    ts=f.ts_start,
                    src_ip=f.src_ip,
                    dst_ip=f.dst_ip,
                    dst_port=f.dst_port,
                    protocol=f.protocol.value,
                    bytes_total=f.bytes_out + f.bytes_in,
                    action=v.action.value,
                    enforced=v.enforced,
                    rule_id=v.rule_id,
                    anomaly_score=v.anomaly_score,
                    labels=",".join(sorted({x.value for x in v.labels}))[:200],
                    host=f.sni or f.dns_qname or (f.l7.http.host if f.l7 and f.l7.http else None),
                    flow=f.model_dump(mode="json"),
                    signals={
                        "anomaly": ev.anomaly.model_dump(mode="json") if ev.anomaly else None,
                        "classifications": [c.model_dump(mode="json") for c in ev.classifications],
                    },
                    verdict=v.model_dump(mode="json"),
                )
                if v.action != Action.ALLOW:
                    alert_id, wants_tier3 = self._attach_alert(s, node_id, ev, v)
                    row.alert_id = alert_id
                    if wants_tier3:
                        tier3.append(alert_id)
                s.add(row)
        for alert_id in tier3:
            try:
                self._tier3.put_nowait(alert_id)
            except queue.Full:
                log.warning("tier3 queue full; alert triage deferred", alert_id=alert_id)

    def _attach_alert(self, s: Session, node_id: str, ev: Evidence, v: Verdict) -> tuple[int, bool]:
        f = ev.flow
        labels = sorted({c.label.value for c in ev.malicious_labels})
        # One incident = one source + one threat. Group by label first so flows that did and
        # did not cross a rule's confidence threshold land in the same alert.
        key = f"{f.src_ip}|{labels[0] if labels else v.rule_id or 'anomaly'}"
        now = time.time()
        alert = s.scalars(
            select(db.Alert).where(
                db.Alert.group_key == key,
                db.Alert.status.in_(("open", "acknowledged")),
                db.Alert.last_seen >= now - ALERT_WINDOW_SECONDS,
            )
        ).first()
        sev = _severity_for(ev, v)
        if alert is None:
            from neurawall.modules.llm_advisor.heuristic import summarize

            summ = summarize([ev])
            alert = db.Alert(
                group_key=key,
                severity=sev,
                title=summ.title[:200],
                summary=summ.summary,
                labels=",".join(labels),
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                node_id=node_id,
                first_seen=f.ts_start,
                last_seen=now,
                recommended_actions=summ.recommended_actions,
                flow_count=0,
            )
            s.add(alert)
            s.flush()
            _alerts_created.inc(severity=sev)
            self._emit("neurawall.alert.created", {"severity": sev})
            self._notify(
                "alert.created",
                str(alert.id),
                {
                    "alert_id": alert.id,
                    "severity": sev,
                    "title": alert.title,
                    "labels": labels,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                },
            )
            new = True
        else:
            new = False
            if SEVERITY_ORDER[sev] > SEVERITY_ORDER[alert.severity]:
                alert.severity = sev
            merged = sorted(set(filter(None, alert.labels.split(","))) | set(labels))
            alert.labels = ",".join(merged)[:200]
        alert.flow_count += 1
        alert.blocked_count += int(v.enforced)
        alert.max_score = max(alert.max_score, v.anomaly_score or 0.0)
        alert.last_seen = now
        wants = False
        if (
            (new or alert.flow_count in (5, 25))
            and not alert.tier3_pending
            and alert.draft_id is None
        ):
            ambiguous = needs_tier3(
                list(ev.classifications),
                self.settings.inference.t3_ambiguous_low,
                self.settings.inference.t3_ambiguous_high,
            )
            if ambiguous or SEVERITY_ORDER[alert.severity] >= 2:
                alert.tier3_pending = True
                wants = True
        return alert.id, wants

    # ------------------------------------------------------------------ flows & evidence

    @staticmethod
    def row_to_evidence(row: db.FlowRow) -> Evidence:
        sig = row.signals or {}
        return Evidence(
            flow=FlowRecord.model_validate(row.flow),
            anomaly=AnomalyScore.model_validate(sig["anomaly"]) if sig.get("anomaly") else None,
            classifications=tuple(
                Classification.model_validate(c) for c in sig.get("classifications", [])
            ),
        )

    def get_flow(self, flow_id: str) -> tuple[db.FlowRow, Evidence, Verdict]:
        with self.db.session() as s:
            row = s.get(db.FlowRow, flow_id)
            if row is None:
                raise NotFound("flow not found")
            s.expunge(row)
        return row, self.row_to_evidence(row), Verdict.model_validate(row.verdict)

    def alert_evidence(self, alert_id: int, limit: int = 40) -> list[Evidence]:
        with self.db.session() as s:
            rows = s.scalars(
                select(db.FlowRow)
                .where(db.FlowRow.alert_id == alert_id)
                .order_by(db.FlowRow.ts.desc())
                .limit(limit)
            ).all()
            return [self.row_to_evidence(r) for r in rows]

    def history(self, limit: int = 20000) -> Iterable[Evidence]:
        since = time.time() - self.settings.policy.simulation_window_seconds
        with self.db.session() as s:
            rows = s.execute(
                select(db.FlowRow.flow, db.FlowRow.signals)
                .where(db.FlowRow.ts >= since)
                .order_by(db.FlowRow.ts.desc())
                .limit(limit)
            ).all()
        for flow, sig in rows:
            yield Evidence(
                flow=FlowRecord.model_validate(flow),
                anomaly=AnomalyScore.model_validate(sig["anomaly"]) if sig.get("anomaly") else None,
                classifications=tuple(
                    Classification.model_validate(c) for c in sig.get("classifications", [])
                ),
            )

    # ------------------------------------------------------------------ drafts & approval

    def simulate(self, match: RuleMatch, action: Action) -> SimulationResult:
        return simulate(
            match, action, self.history(), threshold=self.settings.policy.blast_radius_threshold
        )

    def create_draft(
        self, draft: RuleDraft, *, actor: str, alert_id: int | None = None
    ) -> RuleDraft:
        # Simulation before presentation — mandatory for every draft (blueprint §5.3).
        draft = draft.model_copy(update={"simulation": self.simulate(draft.match, draft.action)})
        with self.db.session() as s:
            s.add(
                db.DraftRow(
                    id=draft.draft_id,
                    data=draft.model_dump(mode="json"),
                    created_by=actor,
                    alert_id=alert_id,
                )
            )
            if alert_id is not None:
                alert = s.get(db.Alert, alert_id)
                if alert is not None:
                    alert.draft_id = draft.draft_id
        self.audit(
            actor,
            "draft.create",
            f"draft:{draft.draft_id}",
            {
                "source": draft.source.value,
                "action": draft.action.value,
                "blast_radius": draft.simulation.blast_radius if draft.simulation else None,
            },
        )
        return draft

    def list_drafts(self, status: str | None = None) -> list[db.DraftRow]:
        with self.db.session() as s:
            q = select(db.DraftRow).order_by(db.DraftRow.created_at.desc()).limit(200)
            if status:
                q = q.where(db.DraftRow.status == status)
            rows = list(s.scalars(q).all())
            for r in rows:
                s.expunge(r)
            return rows

    def get_draft(self, draft_id: str) -> db.DraftRow:
        with self.db.session() as s:
            row = s.get(db.DraftRow, draft_id)
            if row is None:
                raise NotFound("draft not found")
            s.expunge(row)
            return row

    def approve_draft(
        self,
        actor: str,
        draft_id: str,
        *,
        mode: RuleMode,
        note: str = "",
        name: str | None = None,
        priority: int | None = None,
        acknowledge_blast_radius: bool = False,
    ) -> Rule:
        with self.db.session() as s:
            row = s.get(db.DraftRow, draft_id)
            if row is None:
                raise NotFound("draft not found")
            if row.status != "pending":
                raise PolicyViolation(f"draft is already {row.status}")
            if self.settings.policy.require_four_eyes:
                enforce_four_eyes(author=row.created_by, approver=actor)
            draft = RuleDraft.model_validate(row.data)
            # Re-simulate against current traffic: the stored result may be stale.
            sim = self.simulate(draft.match, draft.action)
            if sim.exceeds_threshold and mode == RuleMode.ENFORCE and not acknowledge_blast_radius:
                raise PolicyViolation(
                    f"rule would block {sim.blast_radius:.2%} of recent traffic (threshold "
                    f"{sim.threshold:.2%}); acknowledge the blast radius to enforce it"
                )
            rule = Rule(
                id=self._next_rule_id(s),
                name=name or draft.name,
                rationale=draft.rationale,
                priority=priority if priority is not None else draft.priority,
                action=draft.action,
                mode=mode,
                match=draft.match,
                created_by=row.created_by,
                approved_by=actor,
                description=f"From {draft.source.value} draft {draft_id}. {note}".strip(),
            )
            s.add(db.RuleRow(id=rule.id, data=rule.model_dump(mode="json")))
            row.status, row.decided_by, row.decided_at = "approved", actor, time.time()
            row.decision_note, row.rule_id = note[:2000], rule.id
            row.data = draft.model_copy(update={"simulation": sim}).model_dump(mode="json")
        self.audit(
            actor,
            "draft.approve",
            f"draft:{draft_id}",
            {
                "rule_id": rule.id,
                "mode": mode.value,
                "action": rule.action.value,
                "blast_radius": sim.blast_radius,
                "note": note,
            },
        )
        self.publish_bundle(actor, note=f"{rule.id} approved from draft")
        return rule

    def reject_draft(self, actor: str, draft_id: str, reason: str) -> None:
        with self.db.session() as s:
            row = s.get(db.DraftRow, draft_id)
            if row is None:
                raise NotFound("draft not found")
            if row.status != "pending":
                raise PolicyViolation(f"draft is already {row.status}")
            row.status, row.decided_by, row.decided_at = "rejected", actor, time.time()
            row.decision_note = reason[:2000]
            if row.alert_id is not None:
                alert = s.get(db.Alert, row.alert_id)
                if alert is not None and alert.draft_id == draft_id:
                    alert.draft_id = None
        self.audit(actor, "draft.reject", f"draft:{draft_id}", {"reason": reason})

    def hygiene(self) -> list[dict[str, Any]]:
        return [f.model_dump(mode="json") for f in analyze_hygiene(self.list_rules())]

    # ------------------------------------------------------------------ alerts

    def list_alerts(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[db.Alert], int]:
        with self.db.session() as s:
            q = select(db.Alert)
            if status:
                q = q.where(db.Alert.status == status)
            if severity:
                q = q.where(db.Alert.severity == severity)
            total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
            rows = list(
                s.scalars(q.order_by(db.Alert.last_seen.desc()).offset(offset).limit(limit))
            )
            for r in rows:
                s.expunge(r)
            return rows, total

    def get_alert(self, alert_id: int) -> db.Alert:
        with self.db.session() as s:
            a = s.get(db.Alert, alert_id)
            if a is None:
                raise NotFound("alert not found")
            s.expunge(a)
            return a

    def update_alert(
        self, actor: str, alert_id: int, *, status: str | None = None, assignee: str | None = None
    ) -> db.Alert:
        allowed = {"open", "acknowledged", "resolved", "false_positive"}
        if status and status not in allowed:
            raise ValidationFailure(f"status must be one of {sorted(allowed)}")
        with self.db.session() as s:
            a = s.get(db.Alert, alert_id)
            if a is None:
                raise NotFound("alert not found")
            if status:
                a.status = status
            if assignee is not None:
                a.assignee = assignee or None
            s.flush()
            s.expunge(a)
        self.audit(
            actor, "alert.update", f"alert:{alert_id}", {"status": status, "assignee": assignee}
        )
        return a

    def triage_alert(
        self, alert_id: int, *, draft: bool = True, actor: str = ADVISOR_ACTOR
    ) -> db.Alert:
        """Tier 3: summarise the alert and (optionally) draft a rule for it."""
        evidence = self.alert_evidence(alert_id)
        if not evidence:
            raise NotFound("alert has no flows")
        summary = self.advisor.summarize_alert(evidence)
        with self.db.session() as s:
            a = s.get(db.Alert, alert_id)
            if a is None:
                raise NotFound("alert not found")
            a.title, a.summary = summary.title, summary.summary
            a.summary_source = summary.source.value
            a.recommended_actions = list(summary.recommended_actions)
            if SEVERITY_ORDER[summary.severity.value] > SEVERITY_ORDER[a.severity]:
                a.severity = summary.severity.value
            has_draft = a.draft_id is not None
            # Traffic an existing rule already enforces needs no new rule.
            already_enforced = a.flow_count > 0 and a.blocked_count == a.flow_count
            a.tier3_pending = False
        if draft and not has_draft and not already_enforced:
            d = self.advisor.draft_rule(evidence, self.list_rules())
            duplicate = self._pending_draft_with_match(d.match)
            if duplicate is not None:
                with self.db.session() as s:
                    a = s.get(db.Alert, alert_id)
                    if a is not None:
                        a.draft_id = duplicate
            else:
                self.create_draft(
                    d,
                    actor=ADVISOR_ACTOR if d.source == DraftSource.LLM else "heuristic-advisor",
                    alert_id=alert_id,
                )
        return self.get_alert(alert_id)

    def _pending_draft_with_match(self, match: RuleMatch) -> str | None:
        wanted = match.model_dump(mode="json")
        for row in self.list_drafts("pending"):
            if row.data.get("match") == wanted:
                return row.id
        return None

    def narrate_alert(self, actor: str, alert_id: int) -> dict[str, Any]:
        narrative = self.advisor.narrate_incident(self.alert_evidence(alert_id))
        with self.db.session() as s:
            a = s.get(db.Alert, alert_id)
            if a is None:
                raise NotFound("alert not found")
            a.narrative = narrative.model_dump(mode="json")
        self.audit(actor, "alert.narrate", f"alert:{alert_id}", {"source": narrative.source.value})
        return narrative.model_dump(mode="json")

    def explain_flow(self, flow_id: str) -> dict[str, Any]:
        _, ev, verdict = self.get_flow(flow_id)
        rule = None
        if verdict.rule_id:
            try:
                rule = self.get_rule(verdict.rule_id)
            except NotFound:
                rule = None
        text, source = self.advisor.explain_verdict(verdict, rule, ev)
        return {"explanation": text, "source": source.value}

    # ------------------------------------------------------------------ billing

    #: Keep paid access briefly past period end while Stripe finishes a renewal.
    BILLING_GRACE_SECONDS = 3 * 86400

    @property
    def installation_id(self) -> str:
        with self.db.session() as s:
            row = s.get(db.Setting, "installation_id")
            return str(row.value) if row else ""

    def active_subscription(self) -> db.Subscription | None:
        cutoff = time.time() - self.BILLING_GRACE_SECONDS
        # Linked: only what NEXORA says counts. Standalone: only local Stripe subscriptions.
        # Never both, so a stale row from the other source cannot decide the plan.
        source = (
            db.Subscription.provider == "nexora"
            if self.linked
            else db.Subscription.provider != "nexora"
        )
        with self.db.session() as s:
            sub = s.scalars(
                select(db.Subscription)
                .where(source)
                .where(db.Subscription.status == "active")
                .where(
                    (db.Subscription.current_period_end.is_(None))
                    | (db.Subscription.current_period_end >= cutoff)
                )
                .order_by(db.Subscription.updated_at.desc())
                .limit(1)
            ).first()
            if sub is not None:
                s.expunge(sub)
            return sub

    def plan(self) -> Plan:
        """Active Stripe subscription first, else the configured licence plan.

        Fails closed: anything unrecognised resolves to Community."""
        sub = self.active_subscription()
        return entitlements(sub.plan_id if sub else self.settings.billing.plan)

    def retention_seconds(self) -> int:
        if self.settings.flow_retention_seconds is not None:
            return self.settings.flow_retention_seconds
        days = self.plan().retention_days
        return (days if days is not None else 365) * 86400

    def billing_status(self) -> dict[str, Any]:
        plan = self.plan()
        sub = self.active_subscription()
        with self.db.session() as s:
            nodes = (
                s.scalar(
                    select(func.count()).select_from(db.Node).where(db.Node.revoked.is_(False))
                )
                or 0
            )
        cfg = self.settings.billing
        cfg_n = self.settings.nexora
        return {
            "plan": _plan_dict(plan),
            "source": sub.provider if sub else "licence",
            "linked": self.linked,
            "manage_url": f"{cfg_n.console_url}/billing" if self.linked else None,
            "subscription": None
            if sub is None
            else {
                "status": sub.status,
                "current_period_end": sub.current_period_end,
                "manageable": bool(sub.provider_customer_id),
            },
            "usage": {
                "nodes": nodes,
                "retention_days": self.retention_seconds() // 86400,
                "llm_calls": self.llm_calls_this_period(),
                "llm_budget": self.llm_budget(),
            },
            "self_serve": cfg.self_serve_enabled and not self.linked,
            "plans": [
                _plan_dict(p)
                | {
                    "purchasable": {
                        i: bool(
                            cfg.self_serve_enabled
                            and not self.linked
                            and cfg.price_id(p.plan_id.value, i)
                        )
                        for i in ("month", "year")
                    }
                }
                for p in PLANS.values()
            ],
        }

    # ------------------------------------------------------------------ Claude usage

    #: Usage rows are kept this long: the current and the previous month, for the console.
    LLM_USAGE_KEEP_SECONDS = 62 * 86400

    @staticmethod
    def _llm_period(now: float | None = None) -> tuple[float, float]:
        """The UTC calendar month that contains `now`, as (start, end) epoch seconds."""
        d = datetime.fromtimestamp(now if now is not None else time.time(), UTC)
        start = datetime(d.year, d.month, 1, tzinfo=UTC)
        end = datetime(d.year + (d.month == 12), d.month % 12 + 1, 1, tzinfo=UTC)
        return start.timestamp(), end.timestamp()

    def _record_llm_call(self, rec: CallRecord) -> None:
        self._emit("neurawall.llm.call", {"kind": rec.kind, "outcome": rec.outcome})
        with self.db.session() as s:
            s.add(
                db.LlmUsage(
                    kind=rec.kind,
                    model=rec.model[:60],
                    input_tokens=rec.input_tokens,
                    output_tokens=rec.output_tokens,
                    outcome=rec.outcome,
                )
            )

    def llm_budget(self) -> int | None:
        """Calls per month the plan includes, or None when there is no cap to enforce."""
        plan = self.plan()
        if plan.llm_access != "included":
            return None
        return self.settings.billing.llm_monthly_calls(plan.plan_id.value)

    def llm_calls_this_period(self) -> int:
        start, end = self._llm_period()
        with self.db.session() as s:
            return int(
                s.scalar(
                    select(func.count())
                    .select_from(db.LlmUsage)
                    .where(db.LlmUsage.ts >= start, db.LlmUsage.ts < end)
                    .where(db.LlmUsage.outcome.in_(("ok", "refused")))
                )
                or 0
            )

    def _llm_within_budget(self) -> bool:
        budget = self.llm_budget()
        return budget is None or self.llm_calls_this_period() < budget

    def llm_usage(self) -> dict[str, Any]:
        start, end = self._llm_period()
        plan = self.plan()
        with self.db.session() as s:
            rows = s.execute(
                select(db.LlmUsage.kind, func.count(), func.sum(db.LlmUsage.output_tokens))
                .where(db.LlmUsage.ts >= start, db.LlmUsage.ts < end)
                .group_by(db.LlmUsage.kind)
            ).all()
        return {
            "access": plan.llm_access,
            "used": self.llm_calls_this_period(),
            "budget": self.llm_budget(),
            "period_start": start,
            "period_end": end,
            "by_kind": {k: int(n) for k, n, _ in rows},
            "mode": self.advisor.mode,
        }

    # ------------------------------------------------------------------ notifications

    NOTIFY_EVENTS = ("alert.created", "draft.pending")
    NOTIFY_MAX_ATTEMPTS = 6
    NOTIFY_TESTS_PER_HOUR = 10

    def _notify(self, event_type: str, ref: str, data: dict[str, Any]) -> None:
        """Queue a notification; like `_emit` it never touches the database."""
        self._notify_queue.append((event_type, ref, time.time(), data))

    def _channel_secret(self, ch: db.NotificationChannel) -> str:
        return derive_secret(self.settings.jwt_secret, ch.secret_nonce)

    @staticmethod
    def _check_channel_url(url: str, resolver: Any) -> None:
        check_url(url, **({"resolver": resolver} if resolver else {}))

    def list_channels(self) -> list[dict[str, Any]]:
        with self.db.session() as s:
            channels = s.scalars(
                select(db.NotificationChannel).order_by(db.NotificationChannel.id)
            ).all()
            out = []
            for ch in channels:
                last = s.scalars(
                    select(db.NotificationDelivery)
                    .where(db.NotificationDelivery.channel_id == ch.id)
                    .order_by(db.NotificationDelivery.id.desc())
                    .limit(1)
                ).first()
                out.append(
                    {
                        "id": ch.id,
                        "name": ch.name,
                        # The URL may be a secret (Slack's are): show where it goes, not what it is.
                        "url_hint": _url_hint(ch.url),
                        "events": ch.events,
                        "min_severity": ch.min_severity,
                        "active": ch.active,
                        "created_by": ch.created_by,
                        "created_at": ch.created_at,
                        "last_delivery": None
                        if last is None
                        else {
                            "status": last.status,
                            "http_status": last.http_status,
                            "error": last.error,
                            "at": last.sent_at or last.created_at,
                        },
                    }
                )
            return out

    def create_channel(
        self, actor: str, *, name: str, url: str, events: list[str], min_severity: str
    ) -> tuple[dict[str, Any], str]:
        """Returns the channel and its signing secret, which is shown once."""
        self._check_channel_url(url, self._resolver)
        nonce = secrets.token_hex(16)
        with self.db.session() as s:
            if s.scalars(
                select(db.NotificationChannel).where(db.NotificationChannel.name == name)
            ).first():
                raise ValidationFailure("a channel with this name already exists")
            ch = db.NotificationChannel(
                name=name,
                url=url,
                secret_nonce=nonce,
                events=sorted(set(events)),
                min_severity=min_severity,
                created_by=actor,
            )
            s.add(ch)
            s.flush()
            secret = self._channel_secret(ch)
            channel_id = ch.id
        self.audit(
            actor, "notify.channel_create", f"channel:{channel_id}", {"host": _url_hint(url)}
        )
        return next(c for c in self.list_channels() if c["id"] == channel_id), secret

    def update_channel(
        self,
        actor: str,
        channel_id: int,
        *,
        name: str | None = None,
        url: str | None = None,
        events: list[str] | None = None,
        min_severity: str | None = None,
        active: bool | None = None,
        rotate_secret: bool = False,
    ) -> tuple[dict[str, Any], str | None]:
        if url is not None:
            self._check_channel_url(url, self._resolver)
        secret = None
        with self.db.session() as s:
            ch = s.get(db.NotificationChannel, channel_id)
            if ch is None:
                raise NotFound("channel not found")
            if name is not None and name != ch.name:
                if s.scalars(
                    select(db.NotificationChannel).where(db.NotificationChannel.name == name)
                ).first():
                    raise ValidationFailure("a channel with this name already exists")
                ch.name = name
            if url is not None:
                ch.url = url
            if events is not None:
                ch.events = sorted(set(events))
            if min_severity is not None:
                ch.min_severity = min_severity
            if active is not None:
                ch.active = active
            if rotate_secret:
                ch.secret_nonce = secrets.token_hex(16)
                secret = self._channel_secret(ch)
        self.audit(
            actor,
            "notify.channel_update",
            f"channel:{channel_id}",
            {"url_changed": url is not None, "rotated": rotate_secret, "active": active},
        )
        return next(c for c in self.list_channels() if c["id"] == channel_id), secret

    def delete_channel(self, actor: str, channel_id: int) -> None:
        with self.db.session() as s:
            ch = s.get(db.NotificationChannel, channel_id)
            if ch is None:
                raise NotFound("channel not found")
            s.delete(ch)
        self.audit(actor, "notify.channel_delete", f"channel:{channel_id}")

    def _payload(
        self, event_type: str, ref: str, ts: float, data: dict[str, Any]
    ) -> dict[str, Any]:
        base = self.settings.public_url.rstrip("/")
        if event_type == "alert.created":
            link, text = (
                f"{base}/alerts/{ref}",
                (f"NeuraWall {data.get('severity', '')} alert: {data.get('title', '')}"),
            )
        else:
            link, text = (
                f"{base}/approvals/{ref}",
                "NeuraWall: a rule draft is waiting for approval",
            )
        # `text` makes the same body work with Slack and Teams incoming webhooks.
        return {"event": event_type, "ts": ts, "text": f"{text} {link}", "link": link, "data": data}

    def test_channel(self, actor: str, channel_id: int) -> dict[str, Any]:
        now = time.time()
        self._test_sends = [t for t in self._test_sends if t > now - 3600]
        if len(self._test_sends) >= self.NOTIFY_TESTS_PER_HOUR:
            raise PolicyViolation("test messages were requested too often; try again later")
        self._test_sends.append(now)
        with self.db.session() as s:
            ch = s.get(db.NotificationChannel, channel_id)
            if ch is None:
                raise NotFound("channel not found")
            url, secret = ch.url, self._channel_secret(ch)
        payload = self._payload("test", "test", now, {"message": "This is a test from NeuraWall."})
        payload["text"] = "NeuraWall test message: the webhook is working."
        try:
            status = send_webhook(
                url,
                secret,
                payload,
                now=now,
                **self._send_kwargs(),
            )
            result: dict[str, Any] = {"ok": True, "status": status, "error": None}
        except (WebhookError, ValidationFailure) as exc:
            result = {"ok": False, "status": None, "error": exc.message}
        self.audit(actor, "notify.channel_test", f"channel:{channel_id}", {"ok": result["ok"]})
        return result

    def _send_kwargs(self) -> dict[str, Any]:
        kw: dict[str, Any] = {"transport": self._notify_transport}
        if self._resolver:
            kw["resolver"] = self._resolver
        return kw

    def list_deliveries(
        self, channel_id: int | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        with self.db.session() as s:
            q = select(db.NotificationDelivery).order_by(db.NotificationDelivery.id.desc())
            if channel_id is not None:
                q = q.where(db.NotificationDelivery.channel_id == channel_id)
            return [
                {
                    "id": d.id,
                    "channel_id": d.channel_id,
                    "event_type": d.event_type,
                    "ref": d.ref,
                    "status": d.status,
                    "attempts": d.attempts,
                    "http_status": d.http_status,
                    "error": d.error,
                    "created_at": d.created_at,
                    "sent_at": d.sent_at,
                }
                for d in s.scalars(q.limit(limit)).all()
            ]

    def dispatch_notifications(self) -> int:
        """Turn queued events into deliveries (once per channel and event) and send what is due.
        Returns the number delivered. A failure only reschedules, with backoff; after
        `NOTIFY_MAX_ATTEMPTS` the delivery is marked dead and left for the console to show."""
        batch = []
        while self._notify_queue:
            batch.append(self._notify_queue.popleft())
        now = time.time()
        with self.db.session() as s:
            channels = list(
                s.scalars(
                    select(db.NotificationChannel).where(db.NotificationChannel.active.is_(True))
                ).all()
            )
            for event_type, ref, ts, data in batch:
                for ch in channels:
                    if event_type not in ch.events:
                        continue
                    sev = data.get("severity")
                    if sev and SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER[ch.min_severity]:
                        continue
                    exists = s.scalars(
                        select(db.NotificationDelivery.id).where(
                            db.NotificationDelivery.channel_id == ch.id,
                            db.NotificationDelivery.event_type == event_type,
                            db.NotificationDelivery.ref == ref,
                        )
                    ).first()
                    if exists is None:
                        s.add(
                            db.NotificationDelivery(
                                channel_id=ch.id,
                                event_type=event_type,
                                ref=ref,
                                payload=self._payload(event_type, ref, ts, data),
                                next_try_at=ts,
                            )
                        )
        with self.db.session() as s:
            due = [
                (d.id, d.channel_id, d.payload, d.attempts)
                for d in s.scalars(
                    select(db.NotificationDelivery)
                    .where(
                        db.NotificationDelivery.status == "pending",
                        db.NotificationDelivery.next_try_at <= now,
                    )
                    .order_by(db.NotificationDelivery.id)
                    .limit(50)
                ).all()
            ]
        delivered = 0
        for delivery_id, channel_id, payload, attempts in due:
            with self.db.session() as s:
                channel = s.get(db.NotificationChannel, channel_id)
                if channel is None or not channel.active:
                    continue
                url, secret = channel.url, self._channel_secret(channel)
            status: int | None = None
            error: str | None = None
            dead = False
            try:
                status = send_webhook(url, secret, payload, now=time.time(), **self._send_kwargs())
            except ValidationFailure as exc:
                error, dead = exc.message[:200], True  # the address is not allowed: do not retry
            except WebhookError as exc:
                error = exc.message[:200]
            with self.db.session() as s:
                row = s.get(db.NotificationDelivery, delivery_id)
                if row is None:
                    continue
                row.attempts = attempts + 1
                row.http_status = status
                row.error = error
                if error is None:
                    row.status, row.sent_at = "sent", time.time()
                    delivered += 1
                elif dead or row.attempts >= self.NOTIFY_MAX_ATTEMPTS:
                    row.status = "dead"
                else:
                    row.next_try_at = time.time() + min(3600, 30 * 2**row.attempts)
        return delivered

    def _notify_loop(self) -> None:
        while not self._stop.wait(5):
            try:
                self.dispatch_notifications()
            except Exception:
                log.exception("notification pass failed")

    # ------------------------------------------------------------------ events to NEXORA

    #: Unsent events kept during a long NEXORA outage; the oldest are dropped beyond this.
    OUTBOX_MAX_UNSENT = 50_000
    OUTBOX_BATCH = 100

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        """Queue a usage event (linked installations only). Never touches the database, so it
        is safe inside any session or lock; the outbox thread persists and sends it."""
        cfg = self.settings.nexora
        if cfg.linked and cfg.events_enabled:
            self._events.append((event_type, time.time(), data))

    def _drain_events(self) -> None:
        now = time.time()
        if now - self._last_rollup >= 3600:
            count, self._flows_since_rollup, self._last_rollup = self._flows_since_rollup, 0, now
            if count:
                self._events.append(("neurawall.flows.ingested", now, {"count": count}))
        batch = []
        while self._events:
            batch.append(self._events.popleft())
        if not batch:
            return
        with self.db.session() as s:
            for event_type, ts, data in batch:
                s.add(
                    db.CoreOutbox(
                        event_id=str(uuid.uuid4()),
                        event_type=event_type,
                        payload=data,
                        created_at=ts,
                        next_try_at=ts,
                    )
                )

    def flush_outbox(self) -> int:
        """Persist queued events and send what is due. Returns how many NEXORA accepted.
        A failure only reschedules (exponential backoff, at most an hour apart)."""
        self._drain_events()
        now = time.time()
        with self.db.session() as s:
            due = list(
                s.scalars(
                    select(db.CoreOutbox)
                    .where(db.CoreOutbox.sent_at.is_(None), db.CoreOutbox.next_try_at <= now)
                    .order_by(db.CoreOutbox.id)
                    .limit(self.OUTBOX_BATCH)
                ).all()
            )
            events = [
                {
                    "event_id": r.event_id,
                    "type": r.event_type,
                    "ts": r.created_at,
                    "data": r.payload,
                }
                for r in due
            ]
            ids = [r.id for r in due]
        if not events:
            return 0
        error: str | None = None
        try:
            self._nexora_client().post_events(events)
        except NexoraError as exc:
            error = str(exc)[:200]
        with self.db.session() as s:
            for row in s.scalars(select(db.CoreOutbox).where(db.CoreOutbox.id.in_(ids))).all():
                if error is None:
                    row.sent_at = now
                    row.last_error = None
                else:
                    row.attempts += 1
                    row.last_error = error
                    row.next_try_at = now + min(3600, 30 * 2 ** min(row.attempts, 7))
        return len(events) if error is None else 0

    def purge_outbox(self) -> None:
        now = time.time()
        with self.db.session() as s:
            s.execute(
                delete(db.CoreOutbox).where(
                    db.CoreOutbox.sent_at.is_not(None), db.CoreOutbox.sent_at < now - 7 * 86400
                )
            )
            unsent = s.scalar(
                select(func.count())
                .select_from(db.CoreOutbox)
                .where(db.CoreOutbox.sent_at.is_(None))
            )
            if unsent and unsent > self.OUTBOX_MAX_UNSENT:
                cutoff = s.scalar(
                    select(db.CoreOutbox.id)
                    .where(db.CoreOutbox.sent_at.is_(None))
                    .order_by(db.CoreOutbox.id.desc())
                    .offset(self.OUTBOX_MAX_UNSENT)
                    .limit(1)
                )
                if cutoff is not None:
                    s.execute(
                        delete(db.CoreOutbox).where(
                            db.CoreOutbox.sent_at.is_(None), db.CoreOutbox.id <= cutoff
                        )
                    )

    def outbox_depth(self) -> int:
        with self.db.session() as s:
            return int(
                s.scalar(
                    select(func.count())
                    .select_from(db.CoreOutbox)
                    .where(db.CoreOutbox.sent_at.is_(None))
                )
                or 0
            ) + len(self._events)

    def _outbox_loop(self) -> None:
        while not self._stop.wait(15):
            try:
                self.flush_outbox()
            except Exception:
                log.exception("event outbox pass failed")

    # ------------------------------------------------------------------ NEXORA link

    #: A successful sync keeps the plan valid this long; the billing grace period comes on top.
    #: If NEXORA stays unreachable the plan lapses to Community instead of lasting forever.
    NEXORA_VALID_SECONDS = 4 * 86400
    #: Manual "sync now" presses allowed per hour.
    NEXORA_MANUAL_SYNCS_PER_HOUR = 6

    @property
    def linked(self) -> bool:
        return self.settings.nexora.linked

    def _not_linked(self) -> None:
        if self.linked:
            raise PolicyViolation("billing for this installation is managed in NEXORA")

    def _nexora_client(self) -> NexoraClient:
        cfg = self.settings.nexora
        if cfg.api_key is None:
            raise NexoraError("this installation is not linked to NEXORA")
        return NexoraClient(
            cfg.api_url, cfg.api_key.get_secret_value(), transport=self._nexora_transport
        )

    def _get_setting(self, key: str) -> Any:
        with self.db.session() as s:
            row = s.get(db.Setting, key)
            return row.value if row else None

    def _put_setting(self, key: str, value: Any) -> None:
        with self.db.session() as s:
            row = s.get(db.Setting, key)
            if row is None:
                s.add(db.Setting(key=key, value=value))
            else:
                row.value = value

    def sync_nexora(self, actor: str = "system") -> dict[str, Any]:
        """Pull the organisation's plan from NEXORA and store it as the active subscription.

        Never raises for a NEXORA outage: the failure is recorded and the last good plan keeps
        applying until it expires. Enforcement is unaffected by any outcome here."""
        with self._nexora_lock:
            now = time.time()
            state: dict[str, Any] = dict(self._get_setting("nexora.sync") or {})
            state["last_try"] = now
            try:
                ent = self._nexora_client().fetch_entitlement()
                bound = self.settings.auth.sso_required_org_id
                if bound and ent.org_id != bound:
                    raise NexoraError("the API key belongs to a different organisation")
                plan = entitlements(ent.plan_id)
                valid_until = now + self.NEXORA_VALID_SECONDS
                if ent.current_period_end:
                    valid_until = min(valid_until, float(ent.current_period_end))
                sub_id = f"nexora:{ent.org_id}:neurawall"
                with self.db.session() as s:
                    sub = s.scalars(
                        select(db.Subscription).where(
                            db.Subscription.provider_subscription_id == sub_id
                        )
                    ).first()
                    if sub is None:
                        sub = db.Subscription(provider="nexora", provider_subscription_id=sub_id)
                        s.add(sub)
                    before = sub.plan_id
                    sub.plan_id = plan.plan_id.value
                    sub.status = "active"
                    sub.current_period_end = valid_until
                    sub.updated_at = now
                if before != plan.plan_id.value:
                    self.audit(
                        actor,
                        "billing.nexora_plan_changed",
                        f"org:{ent.org_id}",
                        {"from": before, "to": plan.plan_id.value},
                    )
                state.update(last_ok=now, error=None, org_id=ent.org_id, plan_id=plan.plan_id.value)
            except NexoraError as exc:
                state["error"] = str(exc)
                log.warning("NEXORA sync failed", error=str(exc))
            self._put_setting("nexora.sync", state)
        return self.nexora_status()

    def sync_nexora_manually(self, actor: str) -> dict[str, Any]:
        now = time.time()
        self._manual_syncs = [t for t in self._manual_syncs if t > now - 3600]
        if len(self._manual_syncs) >= self.NEXORA_MANUAL_SYNCS_PER_HOUR:
            raise PolicyViolation("sync was requested too often; try again later")
        self._manual_syncs.append(now)
        return self.sync_nexora(actor)

    def nexora_status(self) -> dict[str, Any]:
        cfg = self.settings.nexora
        state = self._get_setting("nexora.sync") or {}
        sub = self.active_subscription() if self.linked else None
        return {
            "linked": self.linked,
            "organisation": self.settings.auth.sso_required_org_id or state.get("org_id"),
            "api_url": cfg.api_url if self.linked else None,
            "sync_interval_seconds": cfg.sync_interval_seconds,
            "last_ok": state.get("last_ok"),
            "last_try": state.get("last_try"),
            "error": state.get("error"),
            "plan": self.plan().plan_id.value,
            "plan_valid_until": sub.current_period_end if sub else None,
            "events_enabled": self.linked and cfg.events_enabled,
            "events_pending": self.outbox_depth() if self.linked else 0,
        }

    def _nexora_loop(self) -> None:
        interval = self.settings.nexora.sync_interval_seconds
        # A little jitter so many installations do not call in the same second.
        wait = random.uniform(0, 10)  # noqa: S311 - scheduling jitter, not security
        while not self._stop.wait(wait):
            try:
                self.sync_nexora()
            except Exception:
                log.exception("NEXORA sync pass failed")
            wait = interval + random.uniform(0, 300)  # noqa: S311

    def _stripe(self) -> StripeClient:
        cfg = self.settings.billing
        if not cfg.self_serve_enabled or cfg.stripe_secret_key is None:
            raise PolicyViolation("self-serve billing is not enabled on this installation")
        return StripeClient(
            cfg.stripe_secret_key.get_secret_value(),
            portal_configuration_id=cfg.stripe_portal_configuration_id,
        )

    def start_checkout(self, actor: str, *, plan_id: str, interval: str) -> str:
        self._not_linked()
        price = self.settings.billing.price_id(plan_id, interval)
        plan = entitlements(plan_id)
        if plan.plan_id.value != plan_id or not plan.self_serve or not price:
            raise PolicyViolation(f"plan {plan_id!r} ({interval}) is not available for checkout")
        base = f"{self.settings.public_url.rstrip('/')}/billing"
        url = self._stripe().create_checkout(
            price_id=price,
            installation_id=self.installation_id,
            customer_email=actor,
            success_url=f"{base}?checkout=success",
            cancel_url=base,
            plan_id=plan_id,
        )
        self.audit(
            actor, "billing.checkout_started", "billing", {"plan": plan_id, "interval": interval}
        )
        return url

    def start_portal(self, actor: str) -> str:
        self._not_linked()
        sub = self.active_subscription()
        if sub is None or not sub.provider_customer_id:
            raise NotFound("no Stripe subscription to manage")
        url = self._stripe().create_portal(
            customer_id=sub.provider_customer_id,
            return_url=f"{self.settings.public_url.rstrip('/')}/billing",
        )
        self.audit(actor, "billing.portal_opened", "billing")
        return url

    def apply_stripe_webhook(self, raw_body: bytes, signature: str) -> str:
        """Returns "applied" or "ignored"; raises PolicyViolation on a bad signature."""
        if self.linked:
            return "ignored"  # NEXORA owns the subscription; a local one must not compete
        cfg = self.settings.billing
        secret = cfg.stripe_webhook_secret.get_secret_value() if cfg.stripe_webhook_secret else ""
        if not secret:
            return "ignored"
        if not verify_signature(raw_body, signature, secret):
            raise PolicyViolation("invalid Stripe webhook signature")
        try:
            event = interpret_event(
                parse_event(raw_body),
                installation_id=self.installation_id,
                plan_by_price=cfg.plan_by_price(),
            )
        except NotOurEvent:
            return "ignored"
        period_end = event.period_end.timestamp() if event.period_end else None
        with self.db.session() as s:
            sub = s.scalars(
                select(db.Subscription).where(
                    db.Subscription.provider_subscription_id == event.subscription_id
                )
            ).first()
            if sub is None:
                sub = db.Subscription(provider_subscription_id=event.subscription_id)
                s.add(sub)
            before = (sub.plan_id, sub.status)
            sub.plan_id = event.plan_id
            sub.status = event.status
            sub.current_period_end = period_end
            sub.provider_customer_id = event.customer_id or sub.provider_customer_id
            sub.updated_at = time.time()
        if before != (event.plan_id, event.status):
            self.audit(
                "stripe",
                "billing.subscription_updated",
                f"subscription:{event.subscription_id}",
                {"plan": event.plan_id, "status": event.status, "event": event.event_type},
            )
        return "applied"

    # ------------------------------------------------------------------ dashboard

    def dashboard(self, hours: int = 24) -> dict[str, Any]:
        now = time.time()
        since = now - hours * 3600
        bucket = 3600 if hours > 6 else 300
        with self.db.session() as s:
            by_action = dict(
                s.execute(
                    select(db.FlowRow.action, func.count())
                    .where(db.FlowRow.ts >= since)
                    .group_by(db.FlowRow.action)
                ).all()
            )
            enforced = (
                s.scalar(
                    select(func.count())
                    .select_from(db.FlowRow)
                    .where(db.FlowRow.ts >= since, db.FlowRow.enforced.is_(True))
                )
                or 0
            )
            label_rows = s.execute(
                select(db.FlowRow.labels).where(db.FlowRow.ts >= since, db.FlowRow.labels != "")
            ).all()
            labels = Counter(x for (row,) in label_rows for x in row.split(",") if x)
            top_sources = s.execute(
                select(db.FlowRow.src_ip, func.count().label("n"))
                .where(db.FlowRow.ts >= since, db.FlowRow.action != "allow")
                .group_by(db.FlowRow.src_ip)
                .order_by(func.count().desc())
                .limit(8)
            ).all()
            series_rows = s.execute(
                select(
                    (func.floor(db.FlowRow.ts / bucket) * bucket).label("b"),
                    db.FlowRow.action,
                    func.count(),
                )
                .where(db.FlowRow.ts >= since)
                .group_by("b", db.FlowRow.action)
            ).all()
            open_alerts = dict(
                s.execute(
                    select(db.Alert.severity, func.count())
                    .where(db.Alert.status.in_(("open", "acknowledged")))
                    .group_by(db.Alert.severity)
                ).all()
            )
            pending_drafts = (
                s.scalar(
                    select(func.count())
                    .select_from(db.DraftRow)
                    .where(db.DraftRow.status == "pending")
                )
                or 0
            )
            nodes = s.scalars(select(db.Node).where(db.Node.revoked.is_(False))).all()
            node_health = {
                "total": len(nodes),
                "online": sum(1 for n in nodes if n.last_seen and n.last_seen > now - 120),
            }
            active_rules = (
                s.scalar(
                    select(func.count())
                    .select_from(db.RuleRow)
                    .where(db.RuleRow.deleted.is_(False))
                )
                or 0
            )
        series: dict[int, dict[str, int]] = {}
        for b, action, n in series_rows:
            slot = series.setdefault(int(b), {"allow": 0, "alert": 0, "blocked": 0})
            slot["allow" if action == "allow" else "alert" if action == "alert" else "blocked"] += n
        start = int(since // bucket * bucket)
        timeline = [
            {"ts": t, **series.get(t, {"allow": 0, "alert": 0, "blocked": 0})}
            for t in range(start, int(now) + 1, bucket)
        ]
        total = sum(by_action.values())
        return {
            "window_hours": hours,
            "total_flows": total,
            "enforced_blocks": enforced,
            "by_action": by_action,
            "labels": dict(labels.most_common(12)),
            "top_sources": [{"ip": ip, "count": n} for ip, n in top_sources],
            "timeline": timeline,
            "bucket_seconds": bucket,
            "open_alerts": open_alerts,
            "pending_drafts": pending_drafts,
            "nodes": node_health,
            "active_rules": active_rules,
            "bundle_version": self.latest_version(),
            "advisor_mode": self.advisor.mode,
            "tier1_trained": self.anomaly.trained,
        }

    def system_info(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "environment": self.settings.environment,
            "hostname": socket.gethostname(),
            "uptime_seconds": round(time.time() - self.started_at),
            "advisor": {
                "mode": self.advisor.mode,
                "provider": self.settings.llm.provider,
                "model": self.settings.llm.model if self.advisor.backend else None,
                "budget_remaining": self.advisor.budget.remaining,
                "last_error": self.advisor.last_error,
            },
            "signing_key_id": self.signer.key_id,
            "four_eyes": self.settings.policy.require_four_eyes,
            "demo_mode": self.settings.demo_mode,
            "tier1_trained": self.anomaly.trained,
            "database": self.db.engine.dialect.name,
        }

    # ------------------------------------------------------------------ background work

    def _tier3_worker(self) -> None:
        while not self._stop.is_set():
            try:
                alert_id = self._tier3.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self.triage_alert(alert_id)
            except Exception:  # keep the worker alive; Tier 3 is never critical-path
                log.exception("tier3 triage failed", alert_id=alert_id)
                with self.db.session() as s:
                    a = s.get(db.Alert, alert_id)
                    if a is not None:
                        a.tier3_pending = False

    def run_maintenance(self) -> None:
        now = time.time()
        with self.db.session() as s:
            s.execute(delete(db.FlowRow).where(db.FlowRow.ts < now - self.retention_seconds()))
            s.execute(delete(db.NodeHeartbeat).where(db.NodeHeartbeat.ts < now - 7 * 86400))
            s.execute(delete(db.LlmUsage).where(db.LlmUsage.ts < now - self.LLM_USAGE_KEEP_SECONDS))
            rolling = s.scalars(
                select(db.BundleRow).where(db.BundleRow.status == "rolling_out")
            ).all()
            rollouts = [(r.version, r.created_at) for r in rolling]
        for version, _created in rollouts:
            self._evaluate_rollout(version)
        self.purge_outbox()
        with self.db.session() as s:
            s.execute(
                delete(db.NotificationDelivery).where(
                    db.NotificationDelivery.created_at < now - 30 * 86400
                )
            )

    def _evaluate_rollout(self, version: int) -> None:
        dwell = self.settings.policy.rollout_stage_seconds
        with self.db.session() as s:
            last_change = (
                s.scalar(
                    select(func.max(db.AuditRow.ts)).where(
                        db.AuditRow.target == f"bundle:v{version}"
                    )
                )
                or 0
            )
            if time.time() - last_change < dwell:
                return
            since = last_change

            def rate(q: Any) -> tuple[int, int]:
                n = (
                    s.scalar(
                        select(func.count())
                        .select_from(db.FlowRow)
                        .where(q, db.FlowRow.ts >= since)
                    )
                    or 0
                )
                b = (
                    s.scalar(
                        select(func.count())
                        .select_from(db.FlowRow)
                        .where(q, db.FlowRow.ts >= since, db.FlowRow.enforced.is_(True))
                    )
                    or 0
                )
                return n, b

            canary_nodes = [
                n.id for n in s.scalars(select(db.Node).where(db.Node.applied_version == version))
            ]
            cn, cb = rate(db.FlowRow.node_id.in_(canary_nodes)) if canary_nodes else (0, 0)
            bn, bb = rate(db.FlowRow.node_id.not_in(canary_nodes)) if canary_nodes else (0, 0)
        if (
            cn >= 100
            and bn >= 100
            and should_rollback(
                baseline_block_rate=bb / bn,
                canary_block_rate=cb / cn,
                max_increase=self.settings.policy.rollback_block_rate_increase,
            )
        ):
            self.rollback_bundle(
                SYSTEM_ACTOR, version, f"canary block rate {cb / cn:.2%} vs baseline {bb / bn:.2%}"
            )
            return
        self.advance_rollout(SYSTEM_ACTOR, version)

    def _maintenance_loop(self) -> None:
        while not self._stop.wait(30):
            try:
                self.run_maintenance()
            except Exception:
                log.exception("maintenance pass failed")

    def _demo_loop(self) -> None:
        gen = TrafficGenerator(seed=int(time.time()), node_id="demo-sensor")
        # Warm the Tier 1 baseline with benign history first.
        gen.clock = time.time() - 600
        warm = [
            lf.flow
            for lf in gen.stream(max(400, self.settings.inference.baseline_warmup_flows + 50))
        ]
        self.ingest("demo-sensor", warm)
        while not self._stop.wait(2):
            gen.pace(60, 2.0)
            batch = [lf.flow for lf in gen.stream(60, attack_rate=0.002)]
            try:
                self.ingest("demo-sensor", batch)
            except Exception:
                log.exception("demo ingest failed")


def _plan_dict(p: Plan) -> dict[str, Any]:
    return {
        "id": p.plan_id.value,
        "name": p.name,
        "nodes_limit": p.nodes_limit,
        "retention_days": p.retention_days,
        "llm_advisor_allowed": p.llm_advisor_allowed,
        "llm_access": p.llm_access,
        "support": p.support,
        "self_serve": p.self_serve,
        "price_cents_month": p.price_cents_month,
        "price_cents_year": p.price_cents_year,
    }


def _url_hint(url: str) -> str:
    """`https://hooks.example.com/…`: the host only; the path and query may hold a secret."""
    host = url.split("://", 1)[-1].split("/", 1)[0].split("@")[-1]
    return f"https://{host}/…"
