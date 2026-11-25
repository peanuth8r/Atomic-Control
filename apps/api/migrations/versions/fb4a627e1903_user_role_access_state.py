"""Durable user-role revocation state and serialized role updates."""

import sqlalchemy as sa
from alembic import op

revision = "fb4a627e1903"
down_revision = "f83b21c496d0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "user_access_state",
        sa.Column("subject", sa.String(256), primary_key=True),
        sa.Column("invalid_before", sa.Integer(), nullable=False),
        sa.Column("blocked", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.Column("updated_by", sa.String(256), nullable=False),
    )
    table = op.create_table(
        "user_role_lease",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner", sa.String(36), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
    )
    op.bulk_insert(table, [{"id": 1, "owner": "", "expires_at": 0}])


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM user_access_state LIMIT 1")).first():
        raise RuntimeError(
            "Cannot discard persisted role revocations after role edits; reconcile the identity provider and restore a pre-change backup"
        )
    op.drop_table("user_role_lease")
    op.drop_table("user_access_state")
