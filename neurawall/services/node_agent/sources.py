"""Flow sources for the node agent: Zeek log tailing, JSONL tailing, demo generator."""

from __future__ import annotations

import json
import os
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from neurawall.core.logging import get_logger
from neurawall.core.models import FlowRecord
from neurawall.modules.flow_collector.generator import TrafficGenerator
from neurawall.modules.flow_collector.ingest import MAX_LINE_BYTES, zeek_to_flow

log = get_logger(__name__)


class FlowSource(Protocol):
    def poll(self, max_items: int) -> list[dict[str, Any]]: ...


class FileTailer:
    """Tail a growing file; survives truncation and rotation (inode change)."""

    def __init__(self, path: Path, *, from_start: bool = False) -> None:
        self.path = path
        self._fh: Any = None
        self._inode: int | None = None
        self._from_start = from_start
        self._partial = b""

    def _open(self) -> bool:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        if self._fh is not None and self._inode == st.st_ino and self._fh.tell() <= st.st_size:
            return True
        if self._fh is not None:
            self._fh.close()
        self._fh = self.path.open("rb")
        rotated = self._inode is not None
        self._inode = st.st_ino
        if not (self._from_start or rotated):
            self._fh.seek(0, os.SEEK_END)
        self._partial = b""
        return True

    def lines(self, max_lines: int) -> list[bytes]:
        if not self._open():
            return []
        out: list[bytes] = []
        while len(out) < max_lines:
            chunk = self._fh.readline(MAX_LINE_BYTES + 1)
            if not chunk:
                break
            if not chunk.endswith(b"\n"):
                self._partial += chunk
                if len(self._partial) > MAX_LINE_BYTES:
                    self._partial = b""
                break
            line = (self._partial + chunk).strip()
            self._partial = b""
            if line and not line.startswith(b"#") and len(line) <= MAX_LINE_BYTES:
                out.append(line)
        return out


def _loads(line: bytes) -> dict[str, Any] | None:
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    return doc if isinstance(doc, dict) else None


class JsonlSource:
    """Tails a file of NeuraWall FlowRecord JSON objects, one per line."""

    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.tailer = FileTailer(path, from_start=from_start)

    def poll(self, max_items: int) -> list[dict[str, Any]]:
        return [d for d in (_loads(x) for x in self.tailer.lines(max_items)) if d is not None]


class ZeekSource:
    """Tails Zeek JSON logs (``LogAscii::use_json=T``) and joins conn with dns/ssl/http by uid.

    conn.log entries are written when a connection ends, after the protocol logs, so a
    short hold (``join_delay``) is enough to join them.
    """

    def __init__(
        self,
        directory: Path,
        node_id: str = "local",
        join_delay: float = 5.0,
        from_start: bool = False,
    ) -> None:
        self.node_id = node_id
        self.join_delay = join_delay
        self.tailers = {
            n: FileTailer(directory / f"{n}.log", from_start=from_start)
            for n in ("conn", "dns", "ssl", "http")
        }
        self._side: dict[str, OrderedDict[str, dict[str, Any]]] = {
            n: OrderedDict() for n in ("dns", "ssl", "http")
        }
        self._ua_by_host: OrderedDict[str, str] = OrderedDict()
        self._pending: list[tuple[float, dict[str, Any]]] = []

    def _remember(self, kind: str, doc: dict[str, Any]) -> None:
        uid = doc.get("uid")
        if not uid:
            return
        store = self._side[kind]
        store[uid] = doc
        if len(store) > 50_000:
            store.popitem(last=False)
        if kind == "http" and doc.get("user_agent") and doc.get("id.orig_h"):
            self._ua_by_host[doc["id.orig_h"]] = doc["user_agent"]
            if len(self._ua_by_host) > 20_000:
                self._ua_by_host.popitem(last=False)

    def poll(self, max_items: int) -> list[dict[str, Any]]:
        for kind in ("dns", "ssl", "http"):
            for line in self.tailers[kind].lines(10_000):
                doc = _loads(line)
                if doc:
                    self._remember(kind, doc)
        now = time.monotonic()
        for line in self.tailers["conn"].lines(max_items * 2):
            doc = _loads(line)
            if doc:
                self._pending.append((now, doc))
        ready = [c for t, c in self._pending if now - t >= self.join_delay][:max_items]
        self._pending = self._pending[len(ready) :]
        out: list[dict[str, Any]] = []
        for conn in ready:
            uid = conn.get("uid", "")
            try:
                out.append(
                    zeek_to_flow(
                        conn,
                        self._side["dns"].pop(uid, None),
                        self._side["ssl"].pop(uid, None),
                        self._side["http"].pop(uid, None),
                        node_id=self.node_id,
                        ua_by_host=self._ua_by_host,
                    )
                )
            except (KeyError, TypeError, ValueError, ValidationError):
                continue
        return out


class DemoSource:
    """Synthetic traffic with occasional attacks — for trials and demos."""

    def __init__(
        self, node_id: str, rate_per_second: float = 20.0, attack_rate: float = 0.01
    ) -> None:
        self.gen = TrafficGenerator(seed=int(time.time()), node_id=node_id)
        self.rate = rate_per_second
        self.attack_rate = attack_rate
        self._last = time.monotonic()
        self._warm = True

    def poll(self, max_items: int) -> list[dict[str, Any]]:
        if self._warm:
            self._warm = False
            self.gen.clock = time.time() - 600
            flows: list[FlowRecord] = [lf.flow for lf in self.gen.stream(min(max_items, 400))]
        else:
            now = time.monotonic()
            n = min(max_items, int((now - self._last) * self.rate))
            if n <= 0:
                return []
            window = now - self._last
            self._last = now
            self.gen.pace(n, window)
            flows = [lf.flow for lf in self.gen.stream(n, attack_rate=self.attack_rate)]
        return [f.model_dump(mode="json") for f in flows]


def make_source(kind: str, path: str | None, node_id: str) -> FlowSource:
    if kind == "zeek":
        if not path:
            raise ValueError("zeek source requires source_path (Zeek log directory)")
        return ZeekSource(Path(path), node_id=node_id)
    if kind == "jsonl":
        if not path:
            raise ValueError("jsonl source requires source_path")
        return JsonlSource(Path(path))
    if kind == "demo":
        return DemoSource(node_id)
    raise ValueError(f"unknown source {kind!r} (expected zeek, jsonl or demo)")
