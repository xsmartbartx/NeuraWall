"""core outbox: usage events waiting to reach NEXORA

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-10 14:50:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "core_outbox",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=60), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("sent_at", sa.Float(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_try_at", sa.Float(), nullable=False),
        sa.Column("last_error", sa.String(length=200), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
    )


def downgrade() -> None:
    op.drop_table("core_outbox")
