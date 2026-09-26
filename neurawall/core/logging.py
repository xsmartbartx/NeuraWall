"""Structured logging with mandatory redaction (blueprint §9.4).

Redaction is enforced here, at the logging primitive, not left to call sites:
every record passes through :class:`RedactionFilter` before any handler writes it.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import time
import uuid
from typing import Any

_trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_id", default=None)

_SENSITIVE_KEYS = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|set-cookie|session|"
    r"private[_-]?key|credential|payload|body)$",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_URL_QUERY = re.compile(r"(https?://[^\s?#]+|(?<![\w/])/[^\s?#]*)\?[^\s#]*")
_ANTHROPIC_KEY = re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")

REDACTED = "[REDACTED]"
_MAX_STR = 1024


def redact_text(value: str) -> str:
    value = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", value)
    value = _ANTHROPIC_KEY.sub(REDACTED, value)
    value = _JWT.sub(REDACTED, value)
    value = _URL_QUERY.sub(lambda m: m.group(1) + "?" + REDACTED, value)
    if len(value) > _MAX_STR:
        value = value[:_MAX_STR] + "…[truncated]"
    return value


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact a structure: sensitive keys dropped, strings scrubbed."""
    if _depth > 6:
        return "[depth-limit]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            out[key] = REDACTED if _SENSITIVE_KEYS.search(key) else redact(v, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [redact(v, _depth=_depth + 1) for v in value[:50]]
    if isinstance(value, str):
        return redact_text(value)
    return value


def new_trace_id() -> str:
    return uuid.uuid4().hex[:16]


def set_trace_id(trace_id: str | None) -> contextvars.Token[str | None]:
    return _trace_id.set(trace_id)


def get_trace_id() -> str | None:
    return _trace_id.get()


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            record.args = tuple(redact(a) for a in record.args) if isinstance(record.args, tuple) \
                else redact(record.args)
        fields = getattr(record, "fields", None)
        if fields is not None:
            record.fields = redact(fields)
        record.trace_id = get_trace_id() or "-"
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "trace_id": getattr(record, "trace_id", "-"),
        }
        fields = getattr(record, "fields", None)
        if fields:
            doc["fields"] = fields
        if record.exc_info:
            doc["exc"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(doc, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record)} {record.levelname:<7} {record.name} " \
               f"[{getattr(record, 'trace_id', '-')}] {record.getMessage()}"
        fields = getattr(record, "fields", None)
        if fields:
            base += " " + json.dumps(fields, default=str)
        if record.exc_info:
            base += "\n" + redact_text(self.formatException(record.exc_info))
        return base


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactionFilter())
    handler.setFormatter(JsonFormatter() if json_output else TextFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class StructuredLogger(logging.LoggerAdapter[logging.Logger]):
    """``log.info("rule applied", rule_id=...)`` — kwargs become redacted ``fields``."""

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        std = {k: kwargs.pop(k) for k in ("exc_info", "stack_info", "stacklevel") if k in kwargs}
        extra = dict(kwargs.pop("extra", None) or {})
        if kwargs:
            extra["fields"] = dict(kwargs)
            kwargs.clear()
        return msg, {**std, "extra": extra}


def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(logging.getLogger(name), {})
