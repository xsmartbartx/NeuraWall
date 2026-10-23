"""change windows: planned-change suppression of Tier 1 scores

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-20 10:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "change_windows",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cidrs", sa.JSON(), nullable=False),
        sa.Column("starts_at", sa.Float(), nullable=False),
        sa.Column("ends_at", sa.Float(), nullable=False),
        sa.Column("reason", sa.String(length=300), nullable=False),
        sa.Column("created_by", sa.String(length=254), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("cancelled_at", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("change_windows", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_change_windows_starts_at"), ["starts_at"], unique=False
        )
        batch_op.create_index(batch_op.f("ix_change_windows_ends_at"), ["ends_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("change_windows", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_change_windows_ends_at"))
        batch_op.drop_index(batch_op.f("ix_change_windows_starts_at"))
    op.drop_table("change_windows")
