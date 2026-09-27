"""Row -> JSON shapes returned by the API. Never exposes secrets or hashes."""

from __future__ import annotations

import time
from typing import Any

from neurawall.core.models import Verdict
from neurawall.services.control_plane import db


def user(u: db.User) -> dict[str, Any]:
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "active": u.active,
            "must_change_password": u.must_change_password, "created_at": u.created_at,
            "last_login": u.last_login}


def node(n: db.Node, latest_version: int) -> dict[str, Any]:
    online = bool(n.last_seen and n.last_seen > time.time() - 120)
    return {"id": n.id, "name": n.name, "hostname": n.hostname, "agent_version": n.agent_version,
            "backend": n.backend, "applied_version": n.applied_version,
            "up_to_date": n.applied_version == latest_version, "enrolled_at": n.enrolled_at,
            "last_seen": n.last_seen, "status": "revoked" if n.revoked else
            ("online" if online else "offline"), "stats": n.stats or {}}


def draft(d: db.DraftRow) -> dict[str, Any]:
    return {"id": d.id, "status": d.status, "created_by": d.created_by, "created_at": d.created_at,
            "decided_by": d.decided_by, "decided_at": d.decided_at,
            "decision_note": d.decision_note, "rule_id": d.rule_id, "alert_id": d.alert_id,
            "draft": d.data}


def bundle(b: db.BundleRow) -> dict[str, Any]:
    from neurawall.modules.policy_engine import RolloutState

    st = RolloutState(b.version, b.stage_index)
    return {"version": b.version, "created_at": b.created_at, "created_by": b.created_by,
            "rule_count": b.rule_count, "status": b.status, "rollout_percent": st.percent,
            "note": b.note, "key_id": b.envelope.get("key_id")}


def alert(a: db.Alert) -> dict[str, Any]:
    return {"id": a.id, "status": a.status, "severity": a.severity, "title": a.title,
            "summary": a.summary, "summary_source": a.summary_source,
            "labels": [x for x in a.labels.split(",") if x], "src_ip": a.src_ip,
            "dst_ip": a.dst_ip, "node_id": a.node_id, "flow_count": a.flow_count,
            "blocked_count": a.blocked_count, "max_score": round(a.max_score, 3),
            "first_seen": a.first_seen, "last_seen": a.last_seen, "assignee": a.assignee,
            "recommended_actions": a.recommended_actions or [], "narrative": a.narrative,
            "draft_id": a.draft_id, "tier3_pending": a.tier3_pending}


def flow_summary(f: db.FlowRow) -> dict[str, Any]:
    return {"flow_id": f.flow_id, "node_id": f.node_id, "ts": f.ts, "src_ip": f.src_ip,
            "dst_ip": f.dst_ip, "dst_port": f.dst_port, "protocol": f.protocol,
            "bytes": f.bytes_total, "action": f.action, "enforced": f.enforced,
            "rule_id": f.rule_id, "anomaly_score": f.anomaly_score,
            "labels": [x for x in f.labels.split(",") if x], "host": f.host, "alert_id": f.alert_id}


def flow_detail(f: db.FlowRow, verdict: Verdict) -> dict[str, Any]:
    return {**flow_summary(f), "flow": f.flow, "signals": f.signals,
            "verdict": verdict.model_dump(mode="json")}


def audit(a: db.AuditRow) -> dict[str, Any]:
    return {"seq": a.seq, "ts": a.ts, "actor": a.actor, "action": a.action, "target": a.target,
            "detail": a.detail, "hash": a.hash}
