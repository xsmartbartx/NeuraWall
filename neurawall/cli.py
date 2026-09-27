"""``neurawall`` command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from neurawall import __version__


def _server(args: argparse.Namespace) -> int:
    import uvicorn

    from neurawall.core.config import get_settings
    from neurawall.services.control_plane.app import create_app

    settings = get_settings()
    uvicorn.run(create_app(settings), host=args.host or settings.host, port=args.port or settings.port,
                proxy_headers=True, forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
                log_config=None, access_log=False)
    return 0


def _agent_enroll(args: argparse.Namespace) -> int:
    from neurawall.services.node_agent.agent import AgentConfig, NodeAgent, load_config

    cfg = load_config(Path(args.config)) if args.config else AgentConfig(
        control_plane_url=args.url, state_dir=Path(args.state_dir), name=args.name or os.uname().nodename)
    token = args.token or os.environ.get("NEURAWALL_ENROLLMENT_TOKEN") or getpass.getpass("Enrollment token: ")
    state = NodeAgent(cfg, backend=None).enroll(token)
    print(f"Enrolled as {state.node_id}. Pinned bundle-signing key {state.signing_key_id}.")
    print("Verify this key id matches Settings → System in the console before running the agent.")
    return 0


def _agent_run(args: argparse.Namespace) -> int:
    from neurawall.core.logging import configure_logging
    from neurawall.services.node_agent.agent import NodeAgent, load_config

    configure_logging(os.environ.get("NEURAWALL_LOG_LEVEL", "INFO"),
                      json_output=os.environ.get("NEURAWALL_LOG_JSON", "true") == "true")
    NodeAgent(load_config(Path(args.config))).run()
    return 0


def _create_user(args: argparse.Namespace) -> int:
    from neurawall.core.config import get_settings
    from neurawall.security.rbac import Role
    from neurawall.services.control_plane.service import ControlPlane

    password = os.environ.get("NEURAWALL_NEW_USER_PASSWORD") or getpass.getpass("Password: ")
    cp = ControlPlane(get_settings(), advisor_backend=None)
    u = cp.create_user("cli", email=args.email, name=args.name or "", role=Role(args.role), password=password)
    print(f"Created {u.email} ({u.role}); password change required at first login.")
    return 0


def _verify_audit(_: argparse.Namespace) -> int:
    from neurawall.core.config import get_settings
    from neurawall.core.errors import IntegrityFailure
    from neurawall.services.control_plane.service import ControlPlane

    try:
        n = ControlPlane(get_settings(), advisor_backend=None).verify_audit()
    except IntegrityFailure as exc:
        print(f"AUDIT CHAIN INVALID: {exc}", file=sys.stderr)
        return 2
    print(f"Audit chain valid ({n} entries).")
    return 0


def _replay(args: argparse.Namespace) -> int:
    """Send generated traffic to a control plane as an enrolled node (for demos / load tests)."""
    import httpx

    from neurawall.modules.flow_collector.generator import SCENARIOS, TrafficGenerator

    gen = TrafficGenerator(seed=args.seed, node_id="replay")
    headers = {"Authorization": f"Bearer {args.api_key}"}
    flows = [lf.flow for lf in gen.stream(args.count, attack_rate=args.attack_rate)]
    for s in args.scenario or []:
        if s not in SCENARIOS:
            print(f"unknown scenario {s}; choose from {', '.join(SCENARIOS)}", file=sys.stderr)
            return 2
        flows += gen.scenario(s, 20)
    with httpx.Client(base_url=args.url, timeout=60) as c:
        for i in range(0, len(flows), 500):
            r = c.post("/api/v1/agent/flows", headers=headers,
                       json={"flows": [f.model_dump(mode="json") for f in flows[i:i + 500]]})
            r.raise_for_status()
            body = r.json()
            print(f"batch {i // 500 + 1}: accepted={body['accepted']} blocked={len(body['verdicts'])}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="neurawall", description="NeuraWall AI firewall")
    p.add_argument("--version", action="version", version=f"neurawall {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("server", help="run the control plane + console")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=_server)

    agent = sub.add_parser("agent", help="node agent").add_subparsers(dest="agent_cmd", required=True)
    e = agent.add_parser("enroll", help="enroll this node with a control plane")
    e.add_argument("--config", help="agent YAML config (alternative to --url/--state-dir)")
    e.add_argument("--url", default="http://localhost:8080")
    e.add_argument("--state-dir", default="/var/lib/neurawall-agent")
    e.add_argument("--name")
    e.add_argument("--token", help="enrollment token (or NEURAWALL_ENROLLMENT_TOKEN)")
    e.set_defaults(fn=_agent_enroll)
    r = agent.add_parser("run", help="run the agent")
    r.add_argument("--config", required=True)
    r.set_defaults(fn=_agent_run)

    u = sub.add_parser("create-user", help="create a console user")
    u.add_argument("--email", required=True)
    u.add_argument("--name")
    u.add_argument("--role", default="analyst",
                   choices=["viewer", "analyst", "operator", "approver", "admin"])
    u.set_defaults(fn=_create_user)

    v = sub.add_parser("verify-audit", help="verify the tamper-evident audit chain")
    v.set_defaults(fn=_verify_audit)

    rp = sub.add_parser("replay", help="send synthetic traffic to a control plane as a node")
    rp.add_argument("--url", default="http://localhost:8080")
    rp.add_argument("--api-key", required=True)
    rp.add_argument("--count", type=int, default=1000)
    rp.add_argument("--attack-rate", type=float, default=0.01)
    rp.add_argument("--scenario", action="append")
    rp.add_argument("--seed", type=int, default=1)
    rp.set_defaults(fn=_replay)

    args = p.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
