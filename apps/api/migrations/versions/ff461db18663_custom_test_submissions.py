"""Persist append-only custom-test submissions and retained supporting-file hashes."""

import sqlalchemy as sa
from alembic import op

revision = "ff461db18663"
down_revision = "fe351ca07552"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "custom_test_submissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("submitted_by", sa.String(256), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("revision", sa.String(40), nullable=False),
        sa.Column("filename", sa.String(128), nullable=False),
        sa.Column("tests", sa.JSON(), nullable=False),
        sa.Column("files", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("submitted_by", "idempotency_key"),
    )
    op.create_index("ix_custom_test_submissions_revision", "custom_test_submissions", ["revision"])


def downgrade():
    op.drop_table("custom_test_submissions")
