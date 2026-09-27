"""Persistence: SQLAlchemy 2.0 models. SQLite by default, PostgreSQL in production."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


def _now() -> float:
    return time.time()


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(20))
    password_hash: Mapped[str] = mapped_column(String(200))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[float] = mapped_column(Float, default=_now)
    last_login: Mapped[float | None] = mapped_column(Float, nullable=True)


class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str] = mapped_column(String(253), default="")
    agent_version: Mapped[str] = mapped_column(String(40), default="")
    backend: Mapped[str] = mapped_column(String(40), default="")
    applied_version: Mapped[int] = mapped_column(Integer, default=0)
    enrolled_at: Mapped[float] = mapped_column(Float, default=_now)
    last_seen: Mapped[float | None] = mapped_column(Float, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_by: Mapped[str] = mapped_column(String(254))
    created_at: Mapped[float] = mapped_column(Float, default=_now)
    expires_at: Mapped[float] = mapped_column(Float)
    uses_remaining: Mapped[int] = mapped_column(Integer, default=1)
    used_by_node: Mapped[str | None] = mapped_column(String(64), nullable=True)


class RuleRow(Base):
    __tablename__ = "rules"
    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[float] = mapped_column(Float, default=_now)


class DraftRow(Base):
    __tablename__ = "drafts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    created_by: Mapped[str] = mapped_column(String(254))
    created_at: Mapped[float] = mapped_column(Float, default=_now)
    decided_by: Mapped[str | None] = mapped_column(String(254), nullable=True)
    decided_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(8), nullable=True)
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class BundleRow(Base):
    __tablename__ = "bundles"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[float] = mapped_column(Float, default=_now)
    created_by: Mapped[str] = mapped_column(String(254))
    envelope: Mapped[dict[str, Any]] = mapped_column(JSON)
    rule_count: Mapped[int] = mapped_column(Integer)
    stage_index: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="rolling_out")
    note: Mapped[str] = mapped_column(Text, default="")


class FlowRow(Base):
    __tablename__ = "flows"
    flow_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(64), index=True)
    ts: Mapped[float] = mapped_column(Float, index=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8))
    bytes_total: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(16), index=True)
    enforced: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_id: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    labels: Mapped[str] = mapped_column(String(200), default="")
    host: Mapped[str | None] = mapped_column(String(253), nullable=True)
    flow: Mapped[dict[str, Any]] = mapped_column(JSON)
    signals: Mapped[dict[str, Any]] = mapped_column(JSON)
    verdict: Mapped[dict[str, Any]] = mapped_column(JSON)
    alert_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_key: Mapped[str] = mapped_column(String(200), index=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text, default="")
    summary_source: Mapped[str] = mapped_column(String(16), default="heuristic")
    labels: Mapped[str] = mapped_column(String(200), default="")
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    node_id: Mapped[str] = mapped_column(String(64))
    flow_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    max_score: Mapped[float] = mapped_column(Float, default=0.0)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float, index=True)
    assignee: Mapped[str | None] = mapped_column(String(254), nullable=True)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    narrative: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    draft_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tier3_pending: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditRow(Base):
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[float] = mapped_column(Float)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100), index=True)
    target: Mapped[str] = mapped_column(String(200))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)


class NodeHeartbeat(Base):
    __tablename__ = "node_heartbeats"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_id: Mapped[str] = mapped_column(String(64), ForeignKey("nodes.id", ondelete="CASCADE"))
    ts: Mapped[float] = mapped_column(Float, default=_now)
    applied_version: Mapped[int] = mapped_column(Integer)
    blocked: Mapped[int] = mapped_column(Integer, default=0)
    flows: Mapped[int] = mapped_column(Integer, default=0)


Index("ix_flows_alert_ts", FlowRow.alert_id, FlowRow.ts)
Index("ix_heartbeats_node_ts", NodeHeartbeat.node_id, NodeHeartbeat.ts)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        engine = create_engine(
            url, connect_args={"check_same_thread": False, "timeout": 30}, pool_pre_ping=True
        )

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn: Any, _: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20)


MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config(connection: Any) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.attributes["connection"] = connection
    return cfg


def migrate(engine: Engine) -> None:
    """Bring the schema to the latest revision. Idempotent; safe on every start."""
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "head")


class Database:
    def __init__(self, url: str) -> None:
        self.engine = make_engine(url)
        self._factory = sessionmaker(self.engine, expire_on_commit=False)
        migrate(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()
