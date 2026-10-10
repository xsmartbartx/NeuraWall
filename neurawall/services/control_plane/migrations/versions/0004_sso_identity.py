"""sso identity: users.external_id and users.auth_provider

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-10 13:30:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("external_id", sa.String(length=64), nullable=True))
        batch.add_column(
            sa.Column("auth_provider", sa.String(length=12), nullable=False, server_default="local")
        )
        batch.create_unique_constraint("uq_users_external_id", ["external_id"])
        batch.create_check_constraint(
            "ck_users_auth_provider", "auth_provider in ('local', 'nexora')"
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("ck_users_auth_provider", type_="check")
        batch.drop_constraint("uq_users_external_id", type_="unique")
        batch.drop_column("auth_provider")
        batch.drop_column("external_id")
