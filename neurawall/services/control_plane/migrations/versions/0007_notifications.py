"""notifications: webhook channels and their deliveries

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-10 15:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column("secret_nonce", sa.String(length=32), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("min_severity", sa.String(length=10), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=254), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.CheckConstraint(
            "min_severity in ('low', 'medium', 'high', 'critical')", name="ck_channel_severity"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("channel_id", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("ref", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=8), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_try_at", sa.Float(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("sent_at", sa.Float(), nullable=True),
        sa.CheckConstraint("status in ('pending', 'sent', 'dead')", name="ck_delivery_status"),
        sa.ForeignKeyConstraint(["channel_id"], ["notification_channels.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("channel_id", "event_type", "ref", name="uq_delivery_once"),
    )
    op.create_index("ix_delivery_pending", "notification_deliveries", ["status", "next_try_at"])


def downgrade() -> None:
    op.drop_index("ix_delivery_pending", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_table("notification_channels")
