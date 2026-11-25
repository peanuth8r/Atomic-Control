"""Add signed, versioned Linux profile synchronization."""
from alembic import op
import sqlalchemy as sa

revision = "b52f317e908a"
down_revision = "a43d976b2f10"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("actors", sa.Column("profile_sync_protocol", sa.Integer(), server_default="0", nullable=False))
    op.add_column("actors", sa.Column("profile_config_hash", sa.String(64), server_default="", nullable=False))
    op.create_table("profile_syncs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("actors.id"), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.Column("error", sa.String(64), nullable=False),
        sa.UniqueConstraint("actor_id", "generation"))
    op.create_index("ix_profile_syncs_actor_id", "profile_syncs", ["actor_id"])


def downgrade():
    op.drop_table("profile_syncs")
    op.drop_column("actors", "profile_config_hash")
    op.drop_column("actors", "profile_sync_protocol")
