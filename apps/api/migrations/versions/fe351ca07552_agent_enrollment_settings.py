"""Persist administrator-configured initial enrollment lifetime."""

import sqlalchemy as sa
from alembic import op

revision = "fe351ca07552"
down_revision = "fd240b9e5641"
branch_labels = None
depends_on = None


def upgrade():
    settings = op.create_table(
        "agent_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enrollment_token_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.Column("updated_by", sa.String(256), nullable=False),
        sa.CheckConstraint("id = 1", name="agent_settings_singleton"),
        sa.CheckConstraint("enrollment_token_minutes BETWEEN 5 AND 1440", name="agent_enrollment_minutes"),
    )
    op.bulk_insert(
        settings, [{"id": 1, "enrollment_token_minutes": 60, "updated_at": 0, "updated_by": "migration"}]
    )


def downgrade():
    op.drop_table("agent_settings")
