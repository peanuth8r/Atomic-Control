"""Track managed Linux catalog capability and durable installation requests."""
from alembic import op
import sqlalchemy as sa

revision = "e83c195a627b"
down_revision = "d72b084f516a"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("actors", sa.Column("catalog_sync_protocol", sa.Integer(), server_default="0", nullable=False))
    op.add_column("actors", sa.Column("catalog_health", sa.String(24), server_default="unknown", nullable=False))
    op.create_table("catalog_deployments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("actors.id"), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("revision", sa.String(40), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("error", sa.String(64), nullable=False),
        sa.Column("observed_revision", sa.String(40), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("actor_id", "generation"))
    op.create_index("ix_catalog_deployments_actor_id", "catalog_deployments", ["actor_id"])


def downgrade():
    op.drop_table("catalog_deployments")
    op.drop_column("actors", "catalog_health")
    op.drop_column("actors", "catalog_sync_protocol")
