"""Alembic environment. Invoked programmatically by :func:`db.migrate`."""

from __future__ import annotations

from alembic import context

from neurawall.services.control_plane.db import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    connection = config.attributes["connection"]
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=connection.dialect.name == "sqlite", compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


run_migrations_online()
