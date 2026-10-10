"""llm usage: one row per Tier 3 call that reached the model

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-10 14:10:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "llm_usage",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.Float(), nullable=False),
        sa.Column("kind", sa.String(length=12), nullable=False),
        sa.Column("model", sa.String(length=60), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=8), nullable=False),
        sa.CheckConstraint("kind in ('triage', 'draft', 'narrate', 'explain')", name="ck_llm_kind"),
        sa.CheckConstraint("outcome in ('ok', 'refused', 'error')", name="ck_llm_outcome"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_llm_usage_ts", "llm_usage", ["ts"])


def downgrade() -> None:
    op.drop_index("ix_llm_usage_ts", table_name="llm_usage")
    op.drop_table("llm_usage")
