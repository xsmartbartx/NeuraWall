"""Usage events to NEXORA: counts and ids only, at-least-once through a durable outbox,
idempotent on `event_id`, and never in the way of the firewall."""

import json
import time

import pytest

from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner
from neurawall.services.control_plane import db
from neurawall.services.control_plane import service as service_module
from neurawall.services.control_plane.service import ControlPlane
from tests.integration.test_nexora_link import ADMIN, KEY, ORG, FakeNexora, make


@pytest.fixture
def nexora():
    return FakeNexora()


@pytest.fixture
def linked(tmp_path, nexora):
    cp, client = make(tmp_path, nexora)
    with client as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        yield cp, c, {"Authorization": f"Bearer {r.json()['access_token']}"}, nexora


def enroll(c, h, name="edge-1"):
    token = c.post("/api/v1/nodes/enrollment-tokens", headers=h, json={}).json()["token"]
    return c.post("/api/v1/agent/enroll", json={"token": token, "name": name})


def outbox(cp):
    with cp.db.session() as s:
        return s.query(db.CoreOutbox).order_by(db.CoreOutbox.id).all()


def test_standalone_queues_nothing(tmp_path):
    from fastapi.testclient import TestClient

    from neurawall.core.config import load_settings
    from neurawall.services.control_plane.app import create_app

    settings = load_settings(
        environment="test", data_dir=tmp_path, auth={"bootstrap_admin_password": ADMIN[1]}
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    with TestClient(create_app(settings, control_plane=cp, start_background=False)) as c:
        h = {
            "Authorization": "Bearer "
            + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()[
                "access_token"
            ]
        }
        assert enroll(c, h).status_code == 201
    assert len(cp._events) == 0 and cp.outbox_depth() == 0
    assert not any(t.name == "outbox" for t in cp._threads)


def test_events_reach_nexora_once_with_the_key(linked):
    cp, c, h, fake = linked
    assert enroll(c, h).status_code == 201
    assert cp.flush_outbox() >= 1
    req = [r for r in fake.requests if r.url.path == "/v1/events"][-1]
    assert req.method == "POST" and req.headers["authorization"] == f"Bearer {KEY}"
    types = [e["type"] for e in fake.events]
    assert "neurawall.node.enrolled" in types
    assert len({e["event_id"] for e in fake.events}) == len(fake.events)
    assert all(set(e) == {"event_id", "type", "ts", "data"} for e in fake.events)
    assert cp.flush_outbox() == 0  # nothing is sent twice
    assert cp.outbox_depth() == 0


def test_no_address_email_or_flow_field_leaves_the_host(linked):
    cp, c, h, fake = linked
    r = enroll(c, h)
    nh = {"Authorization": f"Bearer {r.json()['api_key']}"}
    gen = TrafficGenerator(seed=5)
    flows = [f.model_dump(mode="json") for f in gen.scenario("command_injection", 20)]
    flows += [f.model_dump(mode="json") for f in (gen.benign() for _ in range(50))]
    assert c.post("/api/v1/agent/flows", headers=nh, json={"flows": flows}).status_code == 200
    cp.flush_outbox()
    sent = json.dumps(fake.events)
    assert "neurawall.alert.created" in sent
    for flow in flows:
        assert flow["src_ip"] not in sent and flow["dst_ip"] not in sent
    assert ADMIN[0] not in sent and KEY not in sent and "edge-1" not in sent


def test_a_failed_send_is_retried_later_with_the_same_event_id(linked, monkeypatch):
    cp, c, h, fake = linked
    enroll(c, h)
    fake.events_status = 500
    assert cp.flush_outbox() == 0
    first = outbox(cp)
    assert first and all(r.attempts == 1 and r.sent_at is None for r in first)
    assert all(r.next_try_at > time.time() for r in first)
    ids = {r.event_id for r in first}
    assert cp.flush_outbox() == 0  # not due yet: no hammering
    fake.events_status = 202
    real = service_module.time.time
    monkeypatch.setattr(service_module.time, "time", lambda: real() + 3600)
    assert cp.flush_outbox() == len(first)
    assert {e["event_id"] for e in fake.events} == ids


def test_events_survive_a_restart(tmp_path, nexora):
    cp, client = make(tmp_path, nexora)
    with client as c:
        r = c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        enroll(c, h)
        nexora.events_status = 503
        cp.flush_outbox()  # persisted, send failed
        pending = {r.event_id for r in outbox(cp)}
    assert pending
    nexora.events_status = 202
    cp2, client2 = make(tmp_path, nexora)  # same data dir = same database
    with client2:
        import time as _t

        cp2.settings  # noqa: B018 - the new process
        with cp2.db.session() as s:
            for row in s.query(db.CoreOutbox).all():
                row.next_try_at = _t.time() - 1
        cp2.flush_outbox()
    assert pending <= {e["event_id"] for e in nexora.events}


def test_batches_are_capped(linked):
    cp, _, _, fake = linked
    already = cp.outbox_depth()  # the first bundle, published at startup
    for _ in range(250):
        cp._emit("neurawall.node.enrolled", {})
    sent = []
    while n := cp.flush_outbox():
        sent.append(n)
    assert max(sent) == 100 and sum(sent) == already + 250
    assert len(fake.events) == already + 250


def test_a_rejected_key_backs_off_and_changes_nothing_else(linked):
    cp, c, h, fake = linked
    cp.sync_nexora()
    fake.events_status = 401
    enroll(c, h)
    assert cp.flush_outbox() == 0
    assert next(r.last_error for r in outbox(cp)) == "NEXORA rejected the API key"
    assert cp.plan().plan_id.value == "pro"  # the plan pull is a separate, unaffected path


def test_events_can_be_turned_off(tmp_path, nexora):
    cp, client = make(tmp_path, nexora, nexora={"api_key": KEY, "events_enabled": False})
    with client as c:
        h = {
            "Authorization": "Bearer "
            + c.post("/api/v1/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]}).json()[
                "access_token"
            ]
        }
        enroll(c, h)
        assert len(cp._events) == 0
        assert not any(t.name == "outbox" for t in cp._threads)


def test_the_hourly_rollup_counts_flows_not_flows_themselves(linked, monkeypatch):
    cp, c, h, fake = linked
    nh = {"Authorization": f"Bearer {enroll(c, h).json()['api_key']}"}
    gen = TrafficGenerator(seed=2)
    flows = [f.model_dump(mode="json") for f in (gen.benign() for _ in range(30))]
    c.post("/api/v1/agent/flows", headers=nh, json={"flows": flows})
    real = service_module.time.time
    monkeypatch.setattr(service_module.time, "time", lambda: real() + 3700)
    cp.flush_outbox()
    rollup = [e for e in fake.events if e["type"] == "neurawall.flows.ingested"]
    assert len(rollup) == 1 and rollup[0]["data"] == {"count": 30}


def test_sent_events_are_purged_and_the_backlog_is_bounded(linked, monkeypatch):
    cp, *_ = linked
    now = time.time()
    with cp.db.session() as s:
        s.add(db.CoreOutbox(event_id="old", event_type="x", payload={}, sent_at=now - 8 * 86400))
        s.add(db.CoreOutbox(event_id="fresh", event_type="x", payload={}, sent_at=now - 60))
    monkeypatch.setattr(ControlPlane, "OUTBOX_MAX_UNSENT", 5)
    with cp.db.session() as s:
        for i in range(12):
            s.add(db.CoreOutbox(event_id=f"u{i}", event_type="x", payload={}))
    cp.purge_outbox()
    ids = [r.event_id for r in outbox(cp)]
    assert "old" not in ids and "fresh" in ids
    assert [i for i in ids if i.startswith("u")] == [f"u{i}" for i in range(7, 12)]


def test_the_status_reports_pending_events(linked):
    _, c, h, _ = linked
    enroll(c, h)
    status = c.get("/api/v1/nexora/status", headers=h).json()
    assert status["events_enabled"] is True and status["events_pending"] >= 1
    assert ORG in (status["organisation"] or "")
