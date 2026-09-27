"""Control-plane core: every workflow, independent of HTTP.

* Ingest: Tier 1 -> Tier 2 -> policy engine for each flow, persisted with signals.
* Alerts: grouped by (source, rule/label) in a 30-minute window; Tier 3 triage queued.
* Rule lifecycle: draft -> simulate -> human approval -> signed bundle -> staged rollout.
* Audit: every enforcement change and approval, hash-chained.
"""

from __future__ import annotations

import queue
import secrets
import socket
import threading
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select, update
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
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.l7_classifier import L7Classifier, needs_tier3
from neurawall.modules.llm_advisor import ClaudeBackend, LlmAdvisor
from neurawall.modules.llm_advisor.advisor import Backend
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
    from neurawall.modules.llm_advisor.heuristic import summarize  # noqa: PLC0415 - cheap, local

    sev = summarize([ev]).severity
    if verdict.enforced and SEVERITY_ORDER[sev] < 2:
        sev = "high"
    return sev


class ControlPlane:
    def __init__(self, settings: Settings, *, signer: Signer | None = None,
                 advisor_backend: Backend | None | str = "auto") -> None:
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = db.Database(settings.resolved_database_url)
        self.signer = signer or FileSigner(settings.data_dir / "keys" / "bundle-signing.pem")
        self.anomaly = AnomalyEngine(warmup_flows=settings.inference.baseline_warmup_flows,
                                     trees=settings.inference.isolation_forest_trees)
        self.classifier = L7Classifier(rate_per_second=settings.inference.t2_rate_per_second)
        self.advisor = LlmAdvisor(self._make_backend(advisor_backend),
                                  max_calls_per_hour=settings.llm.max_calls_per_hour)
        self._engines: dict[int, PolicyEngine] = {}
        self._audit_lock = threading.Lock()
        self._publish_lock = threading.Lock()
        self._ingest_lock = threading.Lock()
        self._tier3: queue.Queue[int] = queue.Queue(maxsize=500)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.started_at = time.time()
        self._bootstrap()

    # ------------------------------------------------------------------ setup

    def _make_backend(self, spec: Backend | None | str) -> Backend | None:
        if spec != "auto":
            return spec  # type: ignore[return-value]
        llm = self.settings.llm
        if llm.provider != "anthropic":
            return None
        key = self.settings.anthropic_api_key
        if not key:
            log.warning("no Anthropic API key configured; Tier 3 runs the offline heuristic advisor")
            return None
        return ClaudeBackend(api_key=key, model=llm.model, max_tokens=llm.max_tokens,
                             effort=llm.effort, timeout_seconds=llm.timeout_seconds,
                             server_side_fallbacks=llm.server_side_fallbacks)

    def _bootstrap(self) -> None:
        with self.db.session() as s:
            if s.scalar(select(func.count()).select_from(db.User)) == 0:
                self._create_bootstrap_admin(s)
            has_bundle = s.scalar(select(func.count()).select_from(db.BundleRow)) > 0
            if not has_bundle and self.settings.policy.starter_rules:
                for rule in starter_rules():
                    s.add(db.RuleRow(id=rule.id, data=rule.model_dump(mode="json")))
        if not has_bundle:
            self.publish_bundle(SYSTEM_ACTOR, note="initial bundle", immediate=True)

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
            log.warning("bootstrap admin created; initial password written to file",
                        email=cfg.bootstrap_admin_email, path=str(path))
        s.add(db.User(email=cfg.bootstrap_admin_email.lower(), name="Administrator",
                      role=Role.ADMIN.value, password_hash=hash_password(password),
                      must_change_password=must_change))

    def start_background(self) -> None:
        self._threads = [
            threading.Thread(target=self._tier3_worker, name="tier3-worker", daemon=True),
            threading.Thread(target=self._maintenance_loop, name="maintenance", daemon=True),
        ]
        if self.settings.demo_mode:
            self._threads.append(threading.Thread(target=self._demo_loop, name="demo", daemon=True))
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self.db.engine.dispose()

    # ------------------------------------------------------------------ audit

    def audit(self, actor: str, action: str, target: str, detail: dict[str, Any] | None = None) -> None:
        with self._audit_lock, self.db.session() as s:
            last = s.scalars(select(db.AuditRow).order_by(db.AuditRow.seq.desc()).limit(1)).first()
            prev = AuditEntry.model_validate(last, from_attributes=True) if last else None
            e = build_entry(prev=prev, ts=time.time(), actor=actor, action=action, target=target,
                            detail=detail)
            s.add(db.AuditRow(**e.model_dump()))

    def verify_audit(self) -> int:
        with self.db.session() as s:
            rows = s.scalars(select(db.AuditRow).order_by(db.AuditRow.seq)).all()
            return verify_chain([AuditEntry.model_validate(r, from_attributes=True) for r in rows])

    # ------------------------------------------------------------------ users & auth

    def login(self, email: str, password: str) -> tuple[str, db.User]:
        with self.db.session() as s:
            user = s.scalars(select(db.User).where(db.User.email == email.lower().strip())).first()
            if user is None or not user.active or not verify_password(password, user.password_hash):
                # Constant-ish work either way to limit user enumeration by timing.
                if user is None:
                    verify_password(password, "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA")
                raise PolicyViolation("invalid email or password")
            user.last_login = time.time()
            token = issue_token(subject=str(user.id), role=user.role, secret=self.settings.jwt_secret,
                                ttl_seconds=self.settings.auth.access_token_ttl_seconds)
            s.expunge(user)
        self.audit(user.email, "auth.login", f"user:{user.id}")
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

    def create_user(self, actor: str, *, email: str, name: str, role: Role, password: str) -> db.User:
        with self.db.session() as s:
            if s.scalars(select(db.User).where(db.User.email == email.lower())).first():
                raise ValidationFailure("a user with this email already exists")
            u = db.User(email=email.lower(), name=name, role=role.value,
                        password_hash=hash_password(password), must_change_password=True)
            s.add(u)
            s.flush()
            s.expunge(u)
        self.audit(actor, "user.create", f"user:{u.id}", {"email": u.email, "role": role.value})
        return u

    def update_user(self, actor: str, user_id: int, *, role: Role | None = None,
                    active: bool | None = None, name: str | None = None) -> db.User:
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None:
                raise NotFound("user not found")
            if (role is not None and role != Role.ADMIN or active is False) and u.role == Role.ADMIN:
                admins = s.scalar(select(func.count()).select_from(db.User).where(
                    db.User.role == Role.ADMIN.value, db.User.active.is_(True)))
                if admins <= 1:
                    raise PolicyViolation("cannot demote or deactivate the last active admin")
            if role is not None:
                u.role = role.value
            if active is not None:
                u.active = active
            if name is not None:
                u.name = name
            s.flush()
            s.expunge(u)
        self.audit(actor, "user.update", f"user:{user_id}",
                   {"role": role.value if role else None, "active": active})
        return u

    def change_password(self, user_id: int, current: str, new: str) -> None:
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None or not verify_password(current, u.password_hash):
                raise PolicyViolation("current password is incorrect")
            u.password_hash = hash_password(new)
            u.must_change_password = False
            email = u.email
        self.audit(email, "user.password_change", f"user:{user_id}")

    def reset_password(self, actor: str, user_id: int) -> str:
        temp = secrets.token_urlsafe(12) + "A1!"
        with self.db.session() as s:
            u = s.get(db.User, user_id)
            if u is None:
                raise NotFound("user not found")
            u.password_hash = hash_password(temp)
            u.must_change_password = True
        self.audit(actor, "user.password_reset", f"user:{user_id}")
        return temp

    # ------------------------------------------------------------------ nodes

    def create_enrollment_token(self, actor: str, ttl_seconds: int = 3600, max_uses: int = 1) -> str:
        token = "nwe_" + secrets.token_urlsafe(24)
        with self.db.session() as s:
            s.add(db.EnrollmentToken(token_hash=hash_api_key(token), created_by=actor,
                                     expires_at=time.time() + ttl_seconds, uses_remaining=max_uses))
        self.audit(actor, "node.enrollment_token", "fleet",
                   {"ttl_seconds": ttl_seconds, "max_uses": max_uses})
        return token

    def enroll_node(self, token: str, *, name: str, hostname: str, agent_version: str,
                    backend: str) -> tuple[db.Node, str]:
        with self.db.session() as s:
            row = s.scalars(select(db.EnrollmentToken).where(
                db.EnrollmentToken.token_hash == hash_api_key(token))).first()
            if row is None or row.uses_remaining <= 0 or row.expires_at < time.time():
                raise PolicyViolation("enrollment token is invalid, used or expired")
            api_key, key_hash = generate_api_key()
            node = db.Node(id="node-" + secrets.token_hex(6), name=name[:120], hostname=hostname[:253],
                           api_key_hash=key_hash, agent_version=agent_version[:40], backend=backend[:40])
            s.add(node)
            row.uses_remaining -= 1
            row.used_by_node = node.id
            s.flush()
            s.expunge(node)
        self.audit("enrollment", "node.enroll", node.id, {"name": name, "hostname": hostname})
        return node, api_key

    def authenticate_node(self, api_key: str) -> db.Node:
        with self.db.session() as s:
            node = s.scalars(select(db.Node).where(db.Node.api_key_hash == hash_api_key(api_key))).first()
            if node is None or node.revoked or not api_key_matches(api_key, node.api_key_hash):
                raise PolicyViolation("unknown or revoked node credentials")
            node.last_seen = time.time()
            s.expunge(node)
            return node

    def heartbeat(self, node_id: str, *, applied_version: int, backend: str,
                  stats: dict[str, Any]) -> None:
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
            s.add(db.NodeHeartbeat(node_id=node_id, applied_version=applied_version,
                                   blocked=int(stats.get("active_blocks", 0) or 0),
                                   flows=int(stats.get("flows_sent", 0) or 0)))

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
            return sorted((Rule.model_validate(r.data) for r in s.scalars(q)),
                          key=lambda r: (r.priority, r.id))

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

    def update_rule(self, actor: str, rule_id: str, *, enabled: bool | None = None,
                    mode: RuleMode | None = None, priority: int | None = None) -> Rule:
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
            rule = rule.model_copy(update={**changes, "version": rule.version + 1, "approved_by": actor})
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
            rules = [Rule.model_validate(r.data)
                     for r in s.scalars(select(db.RuleRow).where(db.RuleRow.deleted.is_(False)))]
            bundle = PolicyBundle(version=version, rules=rules)
            env = sign_bundle(bundle, self.signer)
            s.execute(update(db.BundleRow).where(db.BundleRow.status == "rolling_out")
                      .values(status="superseded"))
            final_stage = len(RolloutState(version, 0).stages) - 1
            s.add(db.BundleRow(version=version, created_by=actor, envelope=env.model_dump(mode="json"),
                               rule_count=len(rules), note=note[:500],
                               stage_index=final_stage if immediate or version == 1 else 0,
                               status="active" if immediate or version == 1 else "rolling_out"))
            self._engines[version] = PolicyEngine(bundle)
        self.audit(actor, "bundle.publish", f"bundle:v{version}",
                   {"rules": len(rules), "note": note, "signing_key": self.signer.key_id})
        return version

    def latest_version(self) -> int:
        with self.db.session() as s:
            return s.scalar(select(func.max(db.BundleRow.version))) or 0

    def engine_for(self, version: int | None = None) -> PolicyEngine:
        if version and version in self._engines:
            return self._engines[version]
        with self.db.session() as s:
            q = select(db.BundleRow).where(db.BundleRow.status != "rolled_back")
            q = q.where(db.BundleRow.version == version) if version else \
                q.order_by(db.BundleRow.version.desc())
            row = s.scalars(q.limit(1)).first()
            if row is None:
                return self.engine_for(None) if version else PolicyEngine(PolicyBundle(version=1, rules=[]))
            env = SignedEnvelope.model_validate(row.envelope)
        engine = PolicyEngine(PolicyBundle.model_validate(env.payload))
        self._engines[engine.version] = engine
        return engine

    def bundle_for_node(self, node_id: str) -> SignedEnvelope:
        """Newest bundle whose rollout stage includes this node (canary 5% -> 25% -> 100%)."""
        with self.db.session() as s:
            rows = s.scalars(select(db.BundleRow).where(db.BundleRow.status != "rolled_back")
                             .order_by(db.BundleRow.version.desc()).limit(20)).all()
            for row in rows:
                st = RolloutState(row.version, row.stage_index)
                if row.status == "active" or st.complete or st.includes(node_id):
                    return SignedEnvelope.model_validate(row.envelope)
        raise NotFound("no policy bundle available")

    def list_bundles(self, limit: int = 50) -> list[db.BundleRow]:
        with self.db.session() as s:
            rows = list(s.scalars(select(db.BundleRow).order_by(db.BundleRow.version.desc())
                                  .limit(limit)).all())
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
                s.execute(update(db.BundleRow).where(db.BundleRow.version < version,
                                                     db.BundleRow.status == "active")
                          .values(status="superseded"))
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
            prev = s.scalars(select(db.BundleRow).where(
                db.BundleRow.version < version, db.BundleRow.status != "rolled_back")
                .order_by(db.BundleRow.version.desc()).limit(1)).first()
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
        self.audit(actor, "bundle.rollback", f"bundle:v{version}",
                   {"reason": reason, "restored_from": prev_version})
        return self.publish_bundle(actor, note=f"rollback of v{version} to rules of v{prev_version}",
                                   immediate=True)

    def public_key(self) -> tuple[str, str]:
        return self.signer.key_id, self.signer.public_key_pem()

    # ------------------------------------------------------------------ ingest pipeline

    def ingest(self, node_id: str, flows: list[FlowRecord], *, node_version: int | None = None) -> IngestOutcome:
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
        blocking = [v for _, v in results if v.enforced]
        return IngestOutcome(len(flows), blocking, engine.version)

    def _persist(self, node_id: str, results: list[tuple[Evidence, Verdict]]) -> None:
        tier3: list[int] = []
        with self.db.session() as s:
            existing = set(s.scalars(select(db.FlowRow.flow_id).where(
                db.FlowRow.flow_id.in_([ev.flow.flow_id for ev, _ in results]))).all())
            for ev, v in results:
                f = ev.flow
                if f.flow_id in existing:
                    continue
                existing.add(f.flow_id)
                row = db.FlowRow(
                    flow_id=f.flow_id, node_id=node_id, ts=f.ts_start, src_ip=f.src_ip,
                    dst_ip=f.dst_ip, dst_port=f.dst_port, protocol=f.protocol.value,
                    bytes_total=f.bytes_out + f.bytes_in, action=v.action.value,
                    enforced=v.enforced, rule_id=v.rule_id, anomaly_score=v.anomaly_score,
                    labels=",".join(sorted({x.value for x in v.labels}))[:200],
                    host=f.sni or f.dns_qname or (f.l7.http.host if f.l7 and f.l7.http else None),
                    flow=f.model_dump(mode="json"),
                    signals={"anomaly": ev.anomaly.model_dump(mode="json") if ev.anomaly else None,
                             "classifications": [c.model_dump(mode="json") for c in ev.classifications]},
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
        key = f"{f.src_ip}|{v.rule_id or (labels[0] if labels else 'anomaly')}"
        now = time.time()
        alert = s.scalars(select(db.Alert).where(
            db.Alert.group_key == key, db.Alert.status.in_(("open", "acknowledged")),
            db.Alert.last_seen >= now - ALERT_WINDOW_SECONDS)).first()
        sev = _severity_for(ev, v)
        if alert is None:
            from neurawall.modules.llm_advisor.heuristic import summarize  # noqa: PLC0415

            summ = summarize([ev])
            alert = db.Alert(group_key=key, severity=sev, title=summ.title[:200], summary=summ.summary,
                             labels=",".join(labels), src_ip=f.src_ip, dst_ip=f.dst_ip,
                             node_id=node_id, first_seen=f.ts_start, last_seen=now,
                             recommended_actions=summ.recommended_actions, flow_count=0)
            s.add(alert)
            s.flush()
            _alerts_created.inc(severity=sev)
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
        if (new or alert.flow_count in (5, 25)) and not alert.tier3_pending and alert.draft_id is None:
            ambiguous = needs_tier3(list(ev.classifications), self.settings.inference.t3_ambiguous_low,
                                    self.settings.inference.t3_ambiguous_high)
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
            classifications=tuple(Classification.model_validate(c) for c in sig.get("classifications", [])),
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
            rows = s.scalars(select(db.FlowRow).where(db.FlowRow.alert_id == alert_id)
                             .order_by(db.FlowRow.ts.desc()).limit(limit)).all()
            return [self.row_to_evidence(r) for r in rows]

    def history(self, limit: int = 20000) -> Iterable[Evidence]:
        since = time.time() - self.settings.policy.simulation_window_seconds
        with self.db.session() as s:
            rows = s.execute(select(db.FlowRow.flow, db.FlowRow.signals)
                             .where(db.FlowRow.ts >= since)
                             .order_by(db.FlowRow.ts.desc()).limit(limit)).all()
        for flow, sig in rows:
            yield Evidence(
                flow=FlowRecord.model_validate(flow),
                anomaly=AnomalyScore.model_validate(sig["anomaly"]) if sig.get("anomaly") else None,
                classifications=tuple(Classification.model_validate(c)
                                      for c in sig.get("classifications", [])),
            )

    # ------------------------------------------------------------------ drafts & approval

    def simulate(self, match: RuleMatch, action: Action) -> SimulationResult:
        return simulate(match, action, self.history(),
                        threshold=self.settings.policy.blast_radius_threshold)

    def create_draft(self, draft: RuleDraft, *, actor: str, alert_id: int | None = None) -> RuleDraft:
        # Simulation before presentation — mandatory for every draft (blueprint §5.3).
        draft = draft.model_copy(update={"simulation": self.simulate(draft.match, draft.action)})
        with self.db.session() as s:
            s.add(db.DraftRow(id=draft.draft_id, data=draft.model_dump(mode="json"),
                              created_by=actor, alert_id=alert_id))
            if alert_id is not None:
                alert = s.get(db.Alert, alert_id)
                if alert is not None:
                    alert.draft_id = draft.draft_id
        self.audit(actor, "draft.create", f"draft:{draft.draft_id}",
                   {"source": draft.source.value, "action": draft.action.value,
                    "blast_radius": draft.simulation.blast_radius if draft.simulation else None})
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

    def approve_draft(self, actor: str, draft_id: str, *, mode: RuleMode, note: str = "",
                      name: str | None = None, priority: int | None = None,
                      acknowledge_blast_radius: bool = False) -> Rule:
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
                    f"{sim.threshold:.2%}); acknowledge the blast radius to enforce it")
            rule = Rule(id=self._next_rule_id(s), name=name or draft.name, rationale=draft.rationale,
                        priority=priority if priority is not None else draft.priority,
                        action=draft.action, mode=mode, match=draft.match,
                        created_by=row.created_by, approved_by=actor,
                        description=f"From {draft.source.value} draft {draft_id}. {note}".strip())
            s.add(db.RuleRow(id=rule.id, data=rule.model_dump(mode="json")))
            row.status, row.decided_by, row.decided_at = "approved", actor, time.time()
            row.decision_note, row.rule_id = note[:2000], rule.id
            row.data = draft.model_copy(update={"simulation": sim}).model_dump(mode="json")
        self.audit(actor, "draft.approve", f"draft:{draft_id}",
                   {"rule_id": rule.id, "mode": mode.value, "action": rule.action.value,
                    "blast_radius": sim.blast_radius, "note": note})
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

    def list_alerts(self, *, status: str | None = None, severity: str | None = None,
                    limit: int = 100, offset: int = 0) -> tuple[list[db.Alert], int]:
        with self.db.session() as s:
            q = select(db.Alert)
            if status:
                q = q.where(db.Alert.status == status)
            if severity:
                q = q.where(db.Alert.severity == severity)
            total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
            rows = list(s.scalars(q.order_by(db.Alert.last_seen.desc()).offset(offset).limit(limit)))
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

    def update_alert(self, actor: str, alert_id: int, *, status: str | None = None,
                     assignee: str | None = None) -> db.Alert:
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
        self.audit(actor, "alert.update", f"alert:{alert_id}", {"status": status, "assignee": assignee})
        return a

    def triage_alert(self, alert_id: int, *, draft: bool = True, actor: str = ADVISOR_ACTOR) -> db.Alert:
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
                self.create_draft(d, actor=ADVISOR_ACTOR if d.source == DraftSource.LLM
                                  else "heuristic-advisor", alert_id=alert_id)
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

    # ------------------------------------------------------------------ dashboard

    def dashboard(self, hours: int = 24) -> dict[str, Any]:
        now = time.time()
        since = now - hours * 3600
        bucket = 3600 if hours > 6 else 300
        with self.db.session() as s:
            by_action = dict(s.execute(select(db.FlowRow.action, func.count())
                                       .where(db.FlowRow.ts >= since).group_by(db.FlowRow.action)).all())
            enforced = s.scalar(select(func.count()).select_from(db.FlowRow).where(
                db.FlowRow.ts >= since, db.FlowRow.enforced.is_(True))) or 0
            label_rows = s.execute(select(db.FlowRow.labels).where(
                db.FlowRow.ts >= since, db.FlowRow.labels != "")).all()
            labels = Counter(x for (row,) in label_rows for x in row.split(",") if x)
            top_sources = s.execute(
                select(db.FlowRow.src_ip, func.count().label("n"))
                .where(db.FlowRow.ts >= since, db.FlowRow.action != "allow")
                .group_by(db.FlowRow.src_ip).order_by(func.count().desc()).limit(8)).all()
            series_rows = s.execute(
                select((func.floor(db.FlowRow.ts / bucket) * bucket).label("b"), db.FlowRow.action,
                       func.count()).where(db.FlowRow.ts >= since)
                .group_by("b", db.FlowRow.action)).all()
            open_alerts = dict(s.execute(select(db.Alert.severity, func.count()).where(
                db.Alert.status.in_(("open", "acknowledged"))).group_by(db.Alert.severity)).all())
            pending_drafts = s.scalar(select(func.count()).select_from(db.DraftRow)
                                      .where(db.DraftRow.status == "pending")) or 0
            nodes = s.scalars(select(db.Node).where(db.Node.revoked.is_(False))).all()
            node_health = {"total": len(nodes),
                           "online": sum(1 for n in nodes if n.last_seen and n.last_seen > now - 120)}
            active_rules = s.scalar(select(func.count()).select_from(db.RuleRow)
                                    .where(db.RuleRow.deleted.is_(False))) or 0
        series: dict[int, dict[str, int]] = {}
        for b, action, n in series_rows:
            slot = series.setdefault(int(b), {"allow": 0, "alert": 0, "blocked": 0})
            slot["allow" if action == "allow" else "alert" if action == "alert" else "blocked"] += n
        start = int(since // bucket * bucket)
        timeline = [{"ts": t, **series.get(t, {"allow": 0, "alert": 0, "blocked": 0})}
                    for t in range(start, int(now) + 1, bucket)]
        total = sum(by_action.values())
        return {
            "window_hours": hours, "total_flows": total, "enforced_blocks": enforced,
            "by_action": by_action, "labels": dict(labels.most_common(12)),
            "top_sources": [{"ip": ip, "count": n} for ip, n in top_sources],
            "timeline": timeline, "bucket_seconds": bucket,
            "open_alerts": open_alerts, "pending_drafts": pending_drafts, "nodes": node_health,
            "active_rules": active_rules, "bundle_version": self.latest_version(),
            "advisor_mode": self.advisor.mode, "tier1_trained": self.anomaly.trained,
        }

    def system_info(self) -> dict[str, Any]:
        return {
            "version": __version__, "environment": self.settings.environment,
            "hostname": socket.gethostname(), "uptime_seconds": round(time.time() - self.started_at),
            "advisor": {"mode": self.advisor.mode, "provider": self.settings.llm.provider,
                        "model": self.settings.llm.model if self.advisor.backend else None,
                        "budget_remaining": self.advisor.budget.remaining,
                        "last_error": self.advisor.last_error},
            "signing_key_id": self.signer.key_id, "four_eyes": self.settings.policy.require_four_eyes,
            "demo_mode": self.settings.demo_mode, "tier1_trained": self.anomaly.trained,
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
            s.execute(delete(db.FlowRow).where(db.FlowRow.ts < now - self.settings.flow_retention_seconds))
            s.execute(delete(db.NodeHeartbeat).where(db.NodeHeartbeat.ts < now - 7 * 86400))
            rolling = s.scalars(select(db.BundleRow).where(db.BundleRow.status == "rolling_out")).all()
            rollouts = [(r.version, r.created_at) for r in rolling]
        for version, _created in rollouts:
            self._evaluate_rollout(version)

    def _evaluate_rollout(self, version: int) -> None:
        dwell = self.settings.policy.rollout_stage_seconds
        with self.db.session() as s:
            last_change = s.scalar(select(func.max(db.AuditRow.ts)).where(
                db.AuditRow.target == f"bundle:v{version}")) or 0
            if time.time() - last_change < dwell:
                return
            since = last_change
            def rate(q: Any) -> tuple[int, int]:
                n = s.scalar(select(func.count()).select_from(db.FlowRow).where(q, db.FlowRow.ts >= since)) or 0
                b = s.scalar(select(func.count()).select_from(db.FlowRow).where(
                    q, db.FlowRow.ts >= since, db.FlowRow.enforced.is_(True))) or 0
                return n, b
            canary_nodes = [n.id for n in s.scalars(select(db.Node).where(db.Node.applied_version == version))]
            cn, cb = rate(db.FlowRow.node_id.in_(canary_nodes)) if canary_nodes else (0, 0)
            bn, bb = rate(db.FlowRow.node_id.not_in(canary_nodes)) if canary_nodes else (0, 0)
        if cn >= 100 and bn >= 100 and should_rollback(
                baseline_block_rate=bb / bn, canary_block_rate=cb / cn,
                max_increase=self.settings.policy.rollback_block_rate_increase):
            self.rollback_bundle(SYSTEM_ACTOR, version,
                                 f"canary block rate {cb / cn:.2%} vs baseline {bb / bn:.2%}")
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
        warm = [lf.flow for lf in gen.stream(max(400, self.settings.inference.baseline_warmup_flows + 50))]
        self.ingest("demo-sensor", warm)
        while not self._stop.wait(2):
            gen.clock = max(gen.clock, time.time() - 2)
            batch = [lf.flow for lf in gen.stream(60, attack_rate=0.002)]
            try:
                self.ingest("demo-sensor", batch)
            except Exception:
                log.exception("demo ingest failed")
