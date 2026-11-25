"""Preserve actor retirement metadata alongside execution history."""
from alembic import op
import sqlalchemy as sa

revision = "c61a742d390f"
down_revision = "b52f317e908a"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("actors", sa.Column("retired_at", sa.Float(), nullable=True))
    op.add_column("actors", sa.Column("retired_by", sa.String(256), nullable=True))
    op.add_column("actors", sa.Column("retirement_reason", sa.Text(), nullable=True))


def downgrade():
    op.drop_column("actors", "retirement_reason")
    op.drop_column("actors", "retired_by")
    op.drop_column("actors", "retired_at")
