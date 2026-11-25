"""Persist encrypted refreshable browser sessions with a fixed expiry."""
from alembic import op
import sqlalchemy as sa

revision = "d72b084f516a"
down_revision = "c61a742d390f"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("browser_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("subject", sa.String(256), nullable=False),
        sa.Column("encrypted_tokens", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("access_expires_at", sa.Float(), nullable=False))
    op.create_index("ix_browser_sessions_expires_at", "browser_sessions", ["expires_at"])


def downgrade():
    op.drop_table("browser_sessions")
