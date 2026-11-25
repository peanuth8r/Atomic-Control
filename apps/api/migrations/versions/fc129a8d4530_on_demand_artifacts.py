"""Immutable per-test artifacts and attempt workspace lifecycle."""

import sqlalchemy as sa
from alembic import op

revision = "fc129a8d4530"
down_revision = "fb4a627e1903"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("actors", sa.Column("workspace_residue", sa.Boolean(), nullable=False, server_default="0"))
    op.create_table(
        "test_artifacts",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("guid", sa.String(36), nullable=False, index=True),
        sa.Column("revision", sa.String(128), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("descriptor", sa.JSON(), nullable=False),
        sa.Column("archive", sa.LargeBinary(), nullable=False),
        sa.Column("approval", sa.JSON(), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.add_column(
        "actors", sa.Column("delivery_mode", sa.String(24), nullable=False, server_default="checkout")
    )
    op.add_column("actors", sa.Column("artifact_protocol", sa.Integer(), nullable=False, server_default="0"))
    op.add_column(
        "atomic_tests", sa.Column("artifact_digest", sa.String(64), nullable=False, server_default="")
    )
    op.add_column("test_approvals", sa.Column("artifact", sa.JSON(), nullable=True))
    op.add_column(
        "execution_attempts",
        sa.Column("workspace_status", sa.String(24), nullable=False, server_default="not_required"),
    )
    op.add_column("execution_attempts", sa.Column("preparation_deadline", sa.Float(), nullable=True))
    op.add_column("execution_attempts", sa.Column("execution_authorized_at", sa.Float(), nullable=True))


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM test_artifacts LIMIT 1")).first():
        raise RuntimeError("Cannot discard artifacts retained for execution evidence and historical cleanup")
    for table, columns in {
        "execution_attempts": ["execution_authorized_at", "preparation_deadline", "workspace_status"],
        "test_approvals": ["artifact"],
        "atomic_tests": ["artifact_digest"],
        "actors": ["workspace_residue", "artifact_protocol", "delivery_mode"],
    }.items():
        with op.batch_alter_table(table) as batch:
            for column in columns:
                batch.drop_column(column)
    op.drop_table("test_artifacts")
