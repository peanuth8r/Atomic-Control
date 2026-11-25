"""Persistent ordered actor execution batches."""

import sqlalchemy as sa
from alembic import op

revision = "f83b21c496d0"
down_revision = "f19d04a672e8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("actors", sa.Column("queue_sequence", sa.Integer(), nullable=False, server_default="0"))
    op.create_table(
        "run_batches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("profile_id", sa.String(36), nullable=False),
        sa.Column("hostname", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("requested_by", sa.String(256), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("approval_mode", sa.String(16), nullable=False),
        sa.Column("failure_policy", sa.String(16), nullable=False),
        sa.Column("paused", sa.Boolean(), nullable=False),
        sa.Column("cancelled", sa.Boolean(), nullable=False),
        sa.Column("pause_reason", sa.String(64), nullable=False),
        sa.Column("pause_run_id", sa.String(36), nullable=True),
        sa.Column("acknowledged_position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.UniqueConstraint("requested_by", "idempotency_key"),
    )
    op.create_index("ix_run_batches_actor_id", "run_batches", ["actor_id"])
    op.add_column("execution_runs", sa.Column("batch_id", sa.String(36), nullable=True))
    op.add_column(
        "execution_runs", sa.Column("queue_position", sa.Integer(), nullable=False, server_default="0")
    )
    op.create_index("ix_execution_runs_batch_id", "execution_runs", ["batch_id"])
    op.create_index("ix_execution_runs_actor_queue", "execution_runs", ["actor_id", "queue_position"])


def downgrade():
    op.drop_index("ix_execution_runs_actor_queue", table_name="execution_runs")
    op.drop_index("ix_execution_runs_batch_id", table_name="execution_runs")
    with op.batch_alter_table("execution_runs") as batch:
        batch.drop_column("queue_position")
        batch.drop_column("batch_id")
    op.drop_table("run_batches")
    op.drop_column("actors", "queue_sequence")
