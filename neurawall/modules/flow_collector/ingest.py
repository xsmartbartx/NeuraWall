"""Flow ingest: validate untrusted flow input and assemble FlowRecords.

Sources supported:

* NeuraWall JSON (the canonical :class:`FlowRecord` shape), one object or JSON Lines.
* Zeek JSON logs — ``conn.log`` joined with ``dns.log``, ``ssl.log`` and ``http.log``
  on ``uid``. This is the recommended production sensor: run Zeek on a SPAN/TAP port
  (or on the host) and point the node agent at its log directory.

Malformed records are counted and dropped, never parsed further (blueprint §9.3(1)).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from neurawall.core.logging import get_logger
from neurawall.core.models import (
    Direction,
    DnsMeta,
    FlowRecord,
    HttpMeta,
    L7Meta,
    Protocol,
    TlsMeta,
)
from neurawall.core.telemetry import REGISTRY

log = get_logger(__name__)
_malformed = REGISTRY.counter("neurawall_ingest_malformed_total", "Malformed flow records dropped")
_accepted = REGISTRY.counter("neurawall_ingest_accepted_total", "Flow records accepted")
MAX_LINE_BYTES = 64 * 1024


@dataclass
class IngestResult:
    flows: list[FlowRecord] = field(default_factory=list)
    rejected: int = 0
    errors: list[str] = field(default_factory=list)


def parse_flows(items: Iterable[Any], *, node_id: str | None = None) -> IngestResult:
    res = IngestResult()
    for i, item in enumerate(items):
        try:
            if not isinstance(item, dict):
                raise ValueError("record is not an object")
            if node_id is not None:
                item = {**item, "node_id": node_id}
            res.flows.append(FlowRecord.model_validate(item))
        except (ValidationError, ValueError) as exc:
            res.rejected += 1
            if len(res.errors) < 5:
                res.errors.append(f"record {i}: {str(exc).splitlines()[0][:200]}")
    _accepted.inc(len(res.flows))
    _malformed.inc(res.rejected)
    return res


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("rb") as fh:
        for raw in fh:
            if len(raw) > MAX_LINE_BYTES:
                _malformed.inc()
                continue
            line = raw.strip()
            if not line or line.startswith(b"#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                _malformed.inc()


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------

_BROWSERS = (
    ("edg/", "edge"),
    ("firefox/", "firefox"),
    ("chrome/", "chrome"),
    ("safari/", "safari"),
)


def claimed_client(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    ua = user_agent.lower()
    for marker, name in _BROWSERS:
        if marker in ua:
            return name
    return None


def _direction(conn: dict[str, Any]) -> Direction:
    lo, lr = conn.get("local_orig"), conn.get("local_resp")
    if lo and lr:
        return Direction.INTERNAL
    if lo:
        return Direction.OUTBOUND
    if lr:
        return Direction.INBOUND
    return Direction.OUTBOUND


def zeek_to_flow(
    conn: dict[str, Any],
    dns: dict[str, Any] | None,
    ssl: dict[str, Any] | None,
    http: dict[str, Any] | None,
    *,
    node_id: str,
    ua_by_host: dict[str, str] | None = None,
) -> dict[str, Any]:
    ts = float(conn["ts"])
    proto = str(conn.get("proto", "tcp")).lower()
    doc: dict[str, Any] = {
        "flow_id": str(conn.get("uid", ""))[:64] or None,
        "node_id": node_id,
        "ts_start": ts,
        "ts_end": ts + float(conn.get("duration") or 0.0),
        "src_ip": conn["id.orig_h"],
        "dst_ip": conn["id.resp_h"],
        "src_port": int(conn.get("id.orig_p", 0)),
        "dst_port": int(conn.get("id.resp_p", 0)),
        "protocol": proto if proto in Protocol.__members__.values() else "tcp",
        "direction": _direction(conn),
        "bytes_out": int(conn.get("orig_ip_bytes") or conn.get("orig_bytes") or 0),
        "bytes_in": int(conn.get("resp_ip_bytes") or conn.get("resp_bytes") or 0),
        "packets_out": int(conn.get("orig_pkts") or 0),
        "packets_in": int(conn.get("resp_pkts") or 0),
        "tcp_flags": str(conn.get("history") or "")[:64],
    }
    if doc["flow_id"] is None:
        del doc["flow_id"]
    l7: dict[str, Any] = {}
    if dns and dns.get("query"):
        l7["dns"] = DnsMeta(
            qname=dns["query"],
            qtype=str(dns.get("qtype_name") or "A")[:10],
            rcode=str(dns.get("rcode_name") or "NOERROR")[:16],
            answers=len(dns.get("answers") or []),
        ).model_dump()
    if http:
        l7["http"] = HttpMeta(
            method=str(http.get("method") or "GET")[:16],
            host=http.get("host"),
            path=str(http.get("uri") or "/")[:2048],
            user_agent=(http.get("user_agent") or None),
            status=http.get("status_code"),
            body_len=int(http.get("request_body_len") or 0),
        ).model_dump()
    if ssl:
        ua = (http or {}).get("user_agent") or (ua_by_host or {}).get(conn["id.orig_h"])
        l7["tls"] = TlsMeta(
            sni=ssl.get("server_name") or None,
            version=ssl.get("version"),
            ja3=ssl.get("ja3"),
            ja4=ssl.get("ja4"),
            claimed_client=claimed_client(ua),
        ).model_dump()
    if l7:
        doc["l7"] = L7Meta.model_validate(l7).model_dump()
    return doc


def read_zeek_dir(directory: Path, *, node_id: str) -> IngestResult:
    """Join one rotation of Zeek JSON logs (conn/dns/ssl/http) into flows."""

    def index(name: str) -> dict[str, dict[str, Any]]:
        p = directory / f"{name}.log"
        return {r["uid"]: r for r in read_jsonl(p) if "uid" in r} if p.exists() else {}

    dns, ssl, http = index("dns"), index("ssl"), index("http")
    ua_by_host = {
        r.get("id.orig_h", ""): r["user_agent"] for r in http.values() if r.get("user_agent")
    }
    docs: list[Any] = []
    conn = directory / "conn.log"
    if conn.exists():
        for c in read_jsonl(conn):
            try:
                uid = c.get("uid", "")
                docs.append(
                    zeek_to_flow(
                        c,
                        dns.get(uid),
                        ssl.get(uid),
                        http.get(uid),
                        node_id=node_id,
                        ua_by_host=ua_by_host,
                    )
                )
            except (KeyError, TypeError, ValueError, ValidationError):
                docs.append(None)  # counted as rejected
    return parse_flows(docs)
