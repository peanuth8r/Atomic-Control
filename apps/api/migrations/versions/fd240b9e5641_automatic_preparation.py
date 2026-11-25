"""Approved file plans, durable packaging and immutable execution bindings."""

import hashlib
import json
import time

import sqlalchemy as sa
from alembic import op

revision = "fd240b9e5641"
down_revision = "fc129a8d4530"
branch_labels = None
depends_on = None


def plan_hash(manifest):
    return hashlib.sha256(
        json.dumps(
            {"manifest": manifest, "packaging_version": 1}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def upgrade():
    op.create_table(
        "artifact_source_blobs",
        sa.Column("digest", sa.String(64), primary_key=True),
        sa.Column("content", sa.LargeBinary(), nullable=False),
    )
    plans = op.create_table(
        "test_file_plans",
        sa.Column("hash", sa.String(64), primary_key=True),
        sa.Column("guid", sa.String(36), nullable=False, index=True),
        sa.Column("revision", sa.String(128), nullable=False),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(24), nullable=False),
        sa.Column("packaging_version", sa.Integer(), nullable=False),
        sa.Column("approval", sa.JSON(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    builds = op.create_table(
        "artifact_builds",
        sa.Column("plan_hash", sa.String(64), sa.ForeignKey("test_file_plans.hash"), primary_key=True),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("artifact_digest", sa.String(64), nullable=False),
        sa.Column("owner", sa.String(36), nullable=False),
        sa.Column("lease_expires_at", sa.Float(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("retry_at", sa.Float(), nullable=False),
        sa.Column("deadline", sa.Float(), nullable=False),
        sa.Column("error", sa.String(512), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
    )
    op.create_table(
        "execution_bindings",
        sa.Column("run_id", sa.String(36), sa.ForeignKey("execution_runs.id"), primary_key=True),
        sa.Column("plan_hash", sa.String(64), sa.ForeignKey("test_file_plans.hash"), nullable=False),
        sa.Column("approved_snapshot_hash", sa.String(64), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("snapshot_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.add_column("test_approvals", sa.Column("plan_hash", sa.String(64), nullable=False, server_default=""))
    op.add_column(
        "execution_runs", sa.Column("preparation_error", sa.String(512), nullable=False, server_default="")
    )
    op.add_column(
        "execution_runs", sa.Column("preparation_code", sa.String(64), nullable=False, server_default="")
    )
    # Preserve exact existing approvals and ready bytes. No network or source execution.
    connection = op.get_bind()
    approvals = sa.Table("test_approvals", sa.MetaData(), autoload_with=connection)
    artifacts = sa.Table("test_artifacts", sa.MetaData(), autoload_with=connection)
    tests = sa.Table("atomic_tests", sa.MetaData(), autoload_with=connection)
    seen = set()
    for row in connection.execute(
        sa.select(approvals, tests.c.catalog_source).join(tests, tests.c.guid == approvals.c.guid)
    ).mappings():
        descriptor = row["artifact"]
        if not row["approved"] or not descriptor:
            continue
        item = (
            connection.execute(
                sa.select(artifacts.c.definition, artifacts.c.revoked, artifacts.c.approval).where(
                    artifacts.c.digest == descriptor["digest"]
                )
            )
            .mappings()
            .first()
        )
        if not item or item["revoked"] or not item["approval"]:
            continue
        manifest = descriptor["manifest"]
        if manifest["definition_hash"] != row["content_hash"] or manifest["revision"] != row["revision"]:
            continue
        key = plan_hash(manifest)
        if key not in seen:
            connection.execute(
                plans.insert().values(
                    hash=key,
                    guid=row["guid"],
                    revision=row["revision"],
                    definition=item["definition"],
                    manifest=manifest,
                    source=row["catalog_source"],
                    packaging_version=1,
                    approval=item["approval"],
                    revoked=False,
                    created_at=time.time(),
                )
            )
            connection.execute(
                builds.insert().values(
                    plan_hash=key,
                    status="ready",
                    artifact_digest=descriptor["digest"],
                    owner="",
                    lease_expires_at=0,
                    attempts=0,
                    retry_at=0,
                    deadline=0,
                    error="",
                    error_code="",
                    updated_at=time.time(),
                )
            )
            seen.add(key)
        connection.execute(approvals.update().where(approvals.c.guid == row["guid"]).values(plan_hash=key))


def downgrade():
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT 1 FROM test_file_plans LIMIT 1")).first():
        raise RuntimeError(
            "Cannot discard approved file plans or their execution bindings; restore a pre-change backup"
        )
    op.drop_table("execution_bindings")
    op.drop_table("artifact_builds")
    op.drop_table("test_file_plans")
    op.drop_table("artifact_source_blobs")
    for table, columns in {
        "execution_runs": ["preparation_code", "preparation_error"],
        "test_approvals": ["plan_hash"],
    }.items():
        with op.batch_alter_table(table) as batch:
            for column in columns:
                batch.drop_column(column)
