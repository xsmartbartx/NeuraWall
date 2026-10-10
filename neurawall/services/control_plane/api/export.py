"""CSV export for flows, alerts and the audit trail.

Two things matter here. A cell that starts with `=`, `+`, `-`, `@`, tab or CR is run as a
formula by spreadsheet software, and several fields (hostnames, alert titles, audit details)
come from network traffic an attacker controls, so such cells get a leading apostrophe.
And an export must not be able to hold the process: it streams page by page and stops at a
hard row cap.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from typing import Any

#: Rows per export. The response says when it was cut short (header `X-Export-Truncated`).
MAX_ROWS = 50_000
PAGE = 500
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas in text; numbers and booleans pass through."""
    if isinstance(value, str) and value.startswith(_FORMULA_STARTS):
        return "'" + value
    return value


def iso(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds") if ts else ""


def stream_csv(
    header: Sequence[str],
    pages: Callable[[int, int], Sequence[Sequence[Any]]],
    *,
    max_rows: int = MAX_ROWS,
) -> Iterator[str]:
    """Yield CSV text. `pages(offset, limit)` returns that slice of rows (empty at the end)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")

    def flush() -> str:
        text = buf.getvalue()
        buf.seek(0)
        buf.truncate()
        return text

    writer.writerow(header)
    yield flush()
    sent = 0
    while sent < max_rows:
        rows = pages(sent, min(PAGE, max_rows - sent))
        if not rows:
            return
        for row in rows:
            writer.writerow([safe_cell(c) for c in row])
        sent += len(rows)
        yield flush()
