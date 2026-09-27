import json

import pytest
from fastapi.testclient import TestClient

from neurawall.core.config import load_settings
from neurawall.core.models import RuleMode
from neurawall.modules.datapath.backends import DryRunBackend
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.security.integrity import EphemeralSigner, sign_payload
from neurawall.services.control_plane.app import create_app
from neurawall.services.control_plane.service import ControlPlane
from neurawall.services.node_agent.agent import AgentConfig, NodeAgent
from neurawall.services.node_agent.sources import FileTailer, JsonlSource


class ListSource:
    def __init__(self, docs):
        self.docs = docs

    def poll(self, n):
        out, self.docs = self.docs[:n], self.docs[n:]
        return out


@pytest.fixture
def env(tmp_path):
    settings = load_settings(
        environment="test",
        data_dir=tmp_path / "cp",
        log_json=False,
        inference={"baseline_warmup_flows": 50, "isolation_forest_trees": 20},
        auth={"bootstrap_admin_password": "Admin-Password-1!"},
    )
    cp = ControlPlane(settings, signer=EphemeralSigner(), advisor_backend=None)
    app = create_app(settings, control_plane=cp, start_background=False)
    with TestClient(app) as http:
        cfg = AgentConfig(
            control_plane_url="http://testserver",
            state_dir=tmp_path / "agent",
            name="edge-1",
            batch_size=1000,
        )
        yield cp, http, cfg


def make_agent(cfg, http, source=None, backend=None):
    return NodeAgent(cfg, backend=backend or DryRunBackend(), source=source, http=http)


def test_enroll_sync_ship_and_enforce(env):
    cp, http, cfg = env
    agent = make_agent(cfg, http)
    agent.enroll(cp.create_enrollment_token("admin"))
    assert (cfg.state_dir / "agent-state.json").stat().st_mode & 0o777 == 0o600
    agent.sync_bundle()
    st = agent.backend.state()
    assert agent.state.applied_version == 1 and st.static_rules + st.dynamic_rules >= 1

    gen = TrafficGenerator(seed=12)
    docs = [gen.benign().model_dump(mode="json") for _ in range(300)]
    docs += [f.model_dump(mode="json") for f in gen.scenario("sql_injection", 10)]
    agent.source = ListSource(docs)
    agent.ship_flows()
    assert agent.stats["flows_sent"] == 310 and agent.stats["verdicts_applied"] >= 1
    assert agent.backend.state().active_blocks >= 1
    agent.heartbeat()
    assert cp.list_nodes()[0].stats["active_blocks"] >= 1


def test_rejects_forged_and_rolled_back_bundles(env):
    cp, http, cfg = env
    agent = make_agent(cfg, http)
    agent.enroll(cp.create_enrollment_token("admin"))
    agent.sync_bundle()
    cp.update_rule("admin", "R-000003", mode=RuleMode.ENFORCE)
    cp.advance_rollout("admin", 2)
    cp.advance_rollout("admin", 2)
    agent.sync_bundle()
    assert agent.state.applied_version == 2

    # Forged: correct key id, wrong signer.
    good = cp.bundle_for_node(agent.state.node_id)
    forged = sign_payload({**good.payload, "version": 99}, EphemeralSigner())
    forged = forged.model_copy(update={"key_id": good.key_id})
    assert not agent.apply_envelope(forged)
    # Replay of an older, validly signed bundle (anti-rollback).
    with cp.db.session() as s:
        from neurawall.core.models import SignedEnvelope
        from neurawall.services.control_plane import db

        v1 = SignedEnvelope.model_validate(s.get(db.BundleRow, 1).envelope)
    assert not agent.apply_envelope(v1)
    assert agent.state.applied_version == 2 and agent.stats["bundle_rejections"] == 2


def test_last_known_good_survives_restart_without_control_plane(env, tmp_path):
    cp, http, cfg = env
    a1 = make_agent(cfg, http)
    a1.enroll(cp.create_enrollment_token("admin"))
    a1.sync_bundle()
    # New process, fresh datapath, control plane unreachable.
    a2 = NodeAgent(
        cfg.model_copy(update={"control_plane_url": "http://127.0.0.1:9"}), backend=DryRunBackend()
    )
    a2.restore_last_known_good()
    assert a2.backend.state().applied_version == 1


def test_file_tailer_handles_partial_lines_and_rotation(tmp_path):
    p = tmp_path / "flows.jsonl"
    p.write_text("")
    src = JsonlSource(p)
    assert src.poll(10) == []
    with p.open("a") as fh:
        fh.write(json.dumps({"a": 1}) + "\n" + '{"b": 2')
    assert src.poll(10) == [{"a": 1}]
    with p.open("a") as fh:
        fh.write("}\n")
    assert src.poll(10) == [{"b": 2}]
    p.unlink()
    p.write_text(json.dumps({"c": 3}) + "\n")  # rotated: new inode, read from start
    assert src.poll(10) == [{"c": 3}]
    assert FileTailer(tmp_path / "missing").lines(5) == []
