"""Track whether run authorization comes from catalog review or per-run approval."""

from alembic import op
import sqlalchemy as sa

revision = "a43d976b2f10"
down_revision = "c98e8cd27531"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("run_approvals", sa.Column("authorization_source", sa.String(length=16), server_default="per_run", nullable=False))


def downgrade():
    op.drop_column("run_approvals", "authorization_source")
