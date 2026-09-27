"""Node agent (blueprint §4.2 ``node-agent``).

* Enrolls once with a single-use token; stores its API key and pins the control plane's
  bundle-signing public key (trust on first use, verifiable out of band).
* Verifies every policy bundle's Ed25519 signature *independently of TLS* and enforces
  monotonic versions (anti-rollback) before handing it to the datapath.
* Keeps the last-known-good bundle on disk: enforcement survives restarts and
  control-plane outages (blueprint §3.3).
* Ships flows from its source to the control plane and applies the enforced verdicts
  it gets back to the datapath's dynamic sets.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from neurawall import __version__
from neurawall.core.errors import IntegrityFailure, RecoverableError
from neurawall.core.logging import get_logger
from neurawall.core.models import FlowRecord, SignedEnvelope, Verdict
from neurawall.modules.datapath.backends import EnforcementBackend, make_backend
from neurawall.modules.policy_engine import open_bundle
from neurawall.security.integrity import load_public_key
from neurawall.services.node_agent.sources import FlowSource, make_source

log = get_logger(__name__)


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_plane_url: str
    state_dir: Path = Path("/var/lib/neurawall-agent")
    name: str = Field(default_factory=socket.gethostname)
    backend: str = "dry-run"
    source: str = "demo"
    source_path: str | None = None
    batch_size: int = Field(500, ge=1, le=5000)
    ship_interval_seconds: float = Field(2.0, gt=0)
    bundle_interval_seconds: float = Field(30.0, gt=0)
    heartbeat_interval_seconds: float = Field(15.0, gt=0)
    ca_bundle: str | None = None
    insecure_skip_tls_verify: bool = False


class AgentState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str
    api_key: str
    signing_key_id: str
    signing_public_key: str
    applied_version: int = 0


class NodeAgent:
    def __init__(
        self,
        cfg: AgentConfig,
        backend: EnforcementBackend | None = None,
        source: FlowSource | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        self.cfg = cfg
        self.backend = backend or make_backend(cfg.backend)
        self.http = http or httpx.Client(
            base_url=cfg.control_plane_url.rstrip("/"),
            timeout=20.0,
            verify=False if cfg.insecure_skip_tls_verify else (cfg.ca_bundle or True),
        )
        self.state: AgentState | None = self._load_state()
        self.source = source
        self._stop = threading.Event()
        self.stats: dict[str, Any] = {
            "flows_sent": 0,
            "flows_rejected": 0,
            "verdicts_applied": 0,
            "bundle_rejections": 0,
            "last_sync_error": None,
        }

    # ---------------------------------------------------------------- state

    @property
    def _state_file(self) -> Path:
        return self.cfg.state_dir / "agent-state.json"

    @property
    def _bundle_file(self) -> Path:
        return self.cfg.state_dir / "last-known-good-bundle.json"

    def _load_state(self) -> AgentState | None:
        if not self._state_file.exists():
            return None
        return AgentState.model_validate_json(self._state_file.read_text())

    def _write_private(self, path: Path, content: str) -> None:
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        tmp.replace(path)

    def _save_state(self) -> None:
        assert self.state is not None
        self._write_private(self._state_file, self.state.model_dump_json(indent=1))

    # ---------------------------------------------------------------- enrollment

    def enroll(self, token: str) -> AgentState:
        r = self.http.post(
            "/api/v1/agent/enroll",
            json={
                "token": token,
                "name": self.cfg.name,
                "hostname": socket.gethostname(),
                "agent_version": __version__,
                "backend": self.backend.name,
            },
        )
        if r.status_code != 201:
            raise RecoverableError(f"enrollment failed ({r.status_code}): {r.text[:300]}")
        body = r.json()
        self.state = AgentState(
            node_id=body["node_id"],
            api_key=body["api_key"],
            signing_key_id=body["signing_key_id"],
            signing_public_key=body["signing_public_key"],
        )
        self._save_state()
        log.info("enrolled", node_id=self.state.node_id, signing_key_id=self.state.signing_key_id)
        return self.state

    def _headers(self) -> dict[str, str]:
        if self.state is None:
            raise RecoverableError("agent is not enrolled; run `neurawall agent enroll` first")
        return {"Authorization": f"Bearer {self.state.api_key}"}

    # ---------------------------------------------------------------- bundles

    def _trusted(self) -> dict[str, Any]:
        assert self.state is not None
        return {self.state.signing_key_id: load_public_key(self.state.signing_public_key)}

    def apply_envelope(self, env: SignedEnvelope, *, persist: bool = True) -> bool:
        assert self.state is not None
        try:
            bundle = open_bundle(env, self._trusted(), min_version=self.state.applied_version)
        except IntegrityFailure as exc:
            self.stats["bundle_rejections"] += 1
            log.error("policy bundle rejected; keeping last-known-good", error=exc.message)
            return False
        if bundle.version == self.backend.state().applied_version:
            return True  # already enforced by the datapath
        result = self.backend.apply_bundle(bundle)
        if not result.ok:
            return False
        self.state.applied_version = bundle.version
        self._save_state()
        if persist:
            self._write_private(self._bundle_file, env.model_dump_json())
        log.info(
            "policy bundle applied",
            version=bundle.version,
            static=result.static_rules,
            dynamic=result.dynamic_rules,
            backend=self.backend.name,
        )
        return True

    def restore_last_known_good(self) -> None:
        if self.state is None or not self._bundle_file.exists():
            return
        env = SignedEnvelope.model_validate_json(self._bundle_file.read_text())
        applied, self.state.applied_version = self.state.applied_version, 0
        if not self.apply_envelope(env, persist=False):
            self.state.applied_version = applied

    def sync_bundle(self) -> None:
        r = self.http.get("/api/v1/agent/bundle", headers=self._headers())
        r.raise_for_status()
        self.apply_envelope(SignedEnvelope.model_validate(r.json()))

    # ---------------------------------------------------------------- flows & heartbeat

    def ship_flows(self) -> int:
        if self.source is None:
            return 0
        assert self.state is not None
        docs = self.source.poll(self.cfg.batch_size)
        if not docs:
            return 0
        r = self.http.post(
            "/api/v1/agent/flows",
            headers=self._headers(),
            json={"applied_version": self.state.applied_version, "flows": docs},
        )
        r.raise_for_status()
        body = r.json()
        self.stats["flows_sent"] += body["accepted"]
        self.stats["flows_rejected"] += body["rejected"]
        for item in body.get("verdicts", []):
            f, v = item["flow"], Verdict.model_validate(item["verdict"])
            flow = FlowRecord(
                flow_id=f["flow_id"],
                src_ip=f["src_ip"],
                dst_ip=f["dst_ip"],
                dst_port=f["dst_port"],
                protocol=f["protocol"],
            )
            if self.backend.apply_verdict(flow, v):
                self.stats["verdicts_applied"] += 1
        return len(docs)

    def heartbeat(self) -> None:
        assert self.state is not None
        st = self.backend.state()
        stats = {
            **self.stats,
            "active_blocks": st.active_blocks,
            "static_rules": st.static_rules,
            "dynamic_rules": st.dynamic_rules,
            "datapath_error": st.last_error,
        }
        r = self.http.post(
            "/api/v1/agent/heartbeat",
            headers=self._headers(),
            json={
                "applied_version": self.state.applied_version,
                "backend": self.backend.name,
                "stats": stats,
            },
        )
        r.raise_for_status()

    # ---------------------------------------------------------------- main loop

    def stop(self, *_: object) -> None:
        self._stop.set()

    def run(self) -> None:
        if self.state is None:
            raise RecoverableError("agent is not enrolled; run `neurawall agent enroll` first")
        if self.source is None:
            self.source = make_source(self.cfg.source, self.cfg.source_path, self.state.node_id)
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        self.restore_last_known_good()
        next_bundle = next_hb = 0.0
        backoff = 1.0
        log.info(
            "agent running",
            node_id=self.state.node_id,
            source=self.cfg.source,
            backend=self.backend.name,
            applied_version=self.state.applied_version,
        )
        while not self._stop.is_set():
            now = time.monotonic()
            try:
                if now >= next_bundle:
                    self.sync_bundle()
                    next_bundle = now + self.cfg.bundle_interval_seconds
                self.ship_flows()
                if now >= next_hb:
                    self.heartbeat()
                    next_hb = now + self.cfg.heartbeat_interval_seconds
                self.stats["last_sync_error"] = None
                backoff = 1.0
                self._stop.wait(self.cfg.ship_interval_seconds)
            except (httpx.HTTPError, RecoverableError) as exc:
                # Control plane unreachable: enforcement continues on last-known-good.
                self.stats["last_sync_error"] = str(exc)[:200]
                log.warning(
                    "control plane sync failed; retrying", error=str(exc)[:200], retry_in=backoff
                )
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)
        log.info("agent stopped")


def load_config(path: Path) -> AgentConfig:
    import yaml

    data = yaml.safe_load(path.read_text()) or {}
    env_url = os.environ.get("NEURAWALL_AGENT_URL")
    if env_url:
        data["control_plane_url"] = env_url
    return AgentConfig.model_validate(data)


def dump_config_example() -> str:
    return json.dumps(
        AgentConfig(control_plane_url="https://neurawall.example.com").model_dump(mode="json"),
        indent=2,
    )
