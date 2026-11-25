import time
import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class AgentSettings(Base):
    __tablename__ = "agent_settings"
    __table_args__ = (
        CheckConstraint("id = 1", name="agent_settings_singleton"),
        CheckConstraint("enrollment_token_minutes BETWEEN 5 AND 1440", name="agent_enrollment_minutes"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    enrollment_token_minutes: Mapped[int] = mapped_column(default=60, server_default="60")
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_by: Mapped[str] = mapped_column(String(256))


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject: Mapped[str] = mapped_column(String(256))
    encrypted_tokens: Mapped[str] = mapped_column(Text)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    access_expires_at: Mapped[float] = mapped_column(Float)


class UserAccessState(Base):
    __tablename__ = "user_access_state"
    subject: Mapped[str] = mapped_column(String(256), primary_key=True)
    invalid_before: Mapped[int] = mapped_column(default=0)
    blocked: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_by: Mapped[str] = mapped_column(String(256))


class UserRoleLease(Base):
    __tablename__ = "user_role_lease"
    id: Mapped[int] = mapped_column(primary_key=True)
    owner: Mapped[str] = mapped_column(String(36))
    expires_at: Mapped[float] = mapped_column(Float)


class Actor(Base):
    __tablename__ = "actors"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    hostname: Mapped[str] = mapped_column(String(128), unique=True)
    registration_state: Mapped[str] = mapped_column(String(24), default="enrolled", server_default="enrolled")
    os: Mapped[str] = mapped_column(default="windows")
    os_version: Mapped[str] = mapped_column(default="")
    agent_version: Mapped[str] = mapped_column(default="")
    revision: Mapped[str] = mapped_column(default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    last_heartbeat: Mapped[float] = mapped_column(Float, default=0)
    health: Mapped[str] = mapped_column(default="unknown")
    delivery_mode: Mapped[str] = mapped_column(String(24), default="checkout", server_default="checkout")
    artifact_protocol: Mapped[int] = mapped_column(default=0, server_default="0")
    workspace_residue: Mapped[bool] = mapped_column(default=False, server_default="0")
    profile_sync_protocol: Mapped[int] = mapped_column(default=0, server_default="0")
    profile_config_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")
    catalog_sync_protocol: Mapped[int] = mapped_column(default=0, server_default="0")
    catalog_health: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    retired_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    retired_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    retirement_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    queue_sequence: Mapped[int] = mapped_column(default=0, server_default="0")


class TestArtifact(Base):
    __tablename__ = "test_artifacts"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    guid: Mapped[str] = mapped_column(String(36), index=True)
    revision: Mapped[str] = mapped_column(String(128))
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    descriptor: Mapped[dict[str, Any]] = mapped_column(JSON)
    archive: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    approval: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    revoked: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class SourceBlob(Base):
    __tablename__ = "artifact_source_blobs"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    content: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)


class FilePlan(Base):
    __tablename__ = "test_file_plans"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    guid: Mapped[str] = mapped_column(String(36), index=True)
    revision: Mapped[str] = mapped_column(String(128))
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSON)
    source: Mapped[str] = mapped_column(String(24))
    packaging_version: Mapped[int] = mapped_column(default=1)
    approval: Mapped[dict[str, Any]] = mapped_column(JSON)
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class ArtifactBuild(Base):
    __tablename__ = "artifact_builds"
    plan_hash: Mapped[str] = mapped_column(ForeignKey("test_file_plans.hash"), primary_key=True)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    artifact_digest: Mapped[str] = mapped_column(String(64), default="")
    owner: Mapped[str] = mapped_column(String(36), default="")
    lease_expires_at: Mapped[float] = mapped_column(Float, default=0)
    attempts: Mapped[int] = mapped_column(default=0)
    retry_at: Mapped[float] = mapped_column(Float, default=0)
    deadline: Mapped[float] = mapped_column(Float, default=0)
    error: Mapped[str] = mapped_column(String(512), default="")
    error_code: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)


class ExecutionBinding(Base):
    __tablename__ = "execution_bindings"
    run_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), primary_key=True)
    plan_hash: Mapped[str] = mapped_column(ForeignKey("test_file_plans.hash"))
    approved_snapshot_hash: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class ProfileSync(Base):
    __tablename__ = "profile_syncs"
    __table_args__ = (UniqueConstraint("actor_id", "generation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id"), index=True)
    generation: Mapped[int] = mapped_column()
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    payload_hash: Mapped[str] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(24), default="pending")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
    results: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(String(64), default="")


class CatalogDeployment(Base):
    __tablename__ = "catalog_deployments"
    __table_args__ = (UniqueConstraint("actor_id", "generation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id"), index=True)
    generation: Mapped[int] = mapped_column()
    revision: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    payload_hash: Mapped[str] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(24), default="pending")
    error: Mapped[str] = mapped_column(String(64), default="")
    observed_revision: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)


class Enrollment(Base):
    __tablename__ = "enrollment_tokens"
    os: Mapped[str] = mapped_column(String(16), default="windows", server_default="windows")
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("actors.id"), nullable=True, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[float] = mapped_column(Float)
    used: Mapped[bool] = mapped_column(default=False)


class Credential(Base):
    __tablename__ = "actor_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id"), index=True)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[float] = mapped_column(Float)
    revoked: Mapped[bool] = mapped_column(default=False)


class Profile(Base):
    __tablename__ = "execution_profiles"
    __table_args__ = (UniqueConstraint("actor_id", "profile_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id"), index=True)
    profile_key: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(128))
    account: Mapped[str] = mapped_column(String(128))
    expected_sid: Mapped[str] = mapped_column(String(184))
    privilege: Mapped[str] = mapped_column(String(16))
    logon_type: Mapped[str] = mapped_column(default="batch")
    enabled: Mapped[bool] = mapped_column(default=True)
    healthy: Mapped[bool] = mapped_column(default=False)


class Revision(Base):
    __tablename__ = "catalog_revisions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    imported_at: Mapped[float] = mapped_column(Float, default=time.time)


class AtomicTest(Base):
    __tablename__ = "atomic_tests"
    guid: Mapped[str] = mapped_column(String(36), primary_key=True)
    technique: Mapped[str] = mapped_column(String(16), index=True)
    name: Mapped[str] = mapped_column(String(256))
    revision: Mapped[str] = mapped_column(ForeignKey("catalog_revisions.id"))
    content_hash: Mapped[str] = mapped_column(String(64))
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    simulated: Mapped[bool] = mapped_column(default=False)
    artifact_digest: Mapped[str] = mapped_column(String(64), default="", server_default="")
    catalog_source: Mapped[str] = mapped_column(
        String(16), default="local", server_default="local", index=True
    )
    source_path: Mapped[str] = mapped_column(String(256), default="", server_default="")
    active: Mapped[bool] = mapped_column(default=True, server_default="1")


class CatalogState(Base):
    __tablename__ = "catalog_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    generation: Mapped[int] = mapped_column(default=0)


class CustomTestSubmission(Base):
    __tablename__ = "custom_test_submissions"
    __table_args__ = (UniqueConstraint("submitted_by", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    submitted_by: Mapped[str] = mapped_column(String(256))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    revision: Mapped[str] = mapped_column(String(40), index=True)
    filename: Mapped[str] = mapped_column(String(128))
    tests: Mapped[list[dict[str, str]]] = mapped_column(JSON)
    files: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class CatalogImport(Base):
    __tablename__ = "catalog_imports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source: Mapped[str] = mapped_column(String(16))
    ref: Mapped[str] = mapped_column(String(128))
    revision: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="fetching", index=True)
    created_by: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
    applied_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    definitions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    files: Mapped[list[dict[str, str]]] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class TestApproval(Base):
    plan_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")
    __tablename__ = "test_approvals"
    guid: Mapped[str] = mapped_column(ForeignKey("atomic_tests.guid"), primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    revision: Mapped[str] = mapped_column(String(128))
    artifact: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    allowed_profiles: Mapped[list[str]] = mapped_column(JSON)
    allowed_platforms: Mapped[list[str]] = mapped_column(JSON)
    risk_level: Mapped[str] = mapped_column(String(16))
    approved_by: Mapped[str] = mapped_column(String(256))
    approved: Mapped[bool] = mapped_column(default=True)


class RunBatch(Base):
    __tablename__ = "run_batches"
    __table_args__ = (UniqueConstraint("requested_by", "idempotency_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(String(36), index=True)
    profile_id: Mapped[str] = mapped_column(String(36))
    hostname: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(128))
    requested_by: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(Text)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    approval_mode: Mapped[str] = mapped_column(String(16))
    failure_policy: Mapped[str] = mapped_column(String(16), default="continue")
    paused: Mapped[bool] = mapped_column(default=False)
    cancelled: Mapped[bool] = mapped_column(default=False)
    pause_reason: Mapped[str] = mapped_column(String(64), default="")
    pause_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    acknowledged_position: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    expires_at: Mapped[float] = mapped_column(Float)


class Run(Base):
    preparation_error: Mapped[str] = mapped_column(String(512), default="", server_default="")
    preparation_code: Mapped[str] = mapped_column(String(64), default="", server_default="")
    __tablename__ = "execution_runs"
    __table_args__ = (
        UniqueConstraint("requested_by", "idempotency_key"),
        Index("ix_execution_runs_actor_queue", "actor_id", "queue_position"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    guid: Mapped[str] = mapped_column(ForeignKey("atomic_tests.guid"), index=True)
    # Immutable historical identifiers; deleting an enrolled host must not erase its evidence.
    actor_id: Mapped[str] = mapped_column(String(36), index=True)
    profile_id: Mapped[str] = mapped_column(String(36))
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("execution_runs.id"), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(256))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(32), default="pending_approval", index=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    updated_at: Mapped[float] = mapped_column(Float, default=time.time)
    cancel_requested: Mapped[bool] = mapped_column(default=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    reconciled: Mapped[bool] = mapped_column(default=False)
    batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    queue_position: Mapped[int] = mapped_column(default=0, server_default="0")


class RunApproval(Base):
    __tablename__ = "run_approvals"
    authorization_source: Mapped[str] = mapped_column(String(16), default="per_run", server_default="per_run")
    run_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), primary_key=True)
    approved_by: Mapped[str] = mapped_column(String(256))
    snapshot_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float)
    decision: Mapped[str] = mapped_column(String(16))


class Attempt(Base):
    __tablename__ = "execution_attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), unique=True)
    started_at: Mapped[float] = mapped_column(Float, default=time.time)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    workspace_status: Mapped[str] = mapped_column(
        String(24), default="not_required", server_default="not_required"
    )
    preparation_deadline: Mapped[float | None] = mapped_column(Float, nullable=True)
    execution_authorized_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    result_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Lease(Base):
    __tablename__ = "job_leases"
    actor_id: Mapped[str] = mapped_column(ForeignKey("actors.id"), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), unique=True)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("execution_attempts.id"), unique=True)
    fence: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float)


class Event(Base):
    __tablename__ = "execution_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    run_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    status: Mapped[str] = mapped_column(String(32))
    identity: Mapped[str] = mapped_column(String(256))
    timestamp: Mapped[float] = mapped_column(Float, default=time.time)


class Log(Base):
    __tablename__ = "execution_logs"
    run_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), primary_key=True)
    content: Mapped[str] = mapped_column(Text)
    truncated: Mapped[bool] = mapped_column(default=False)


class Cleanup(Base):
    __tablename__ = "cleanup_runs"
    id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), primary_key=True)
    parent_id: Mapped[str] = mapped_column(ForeignKey("execution_runs.id"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending_approval")


class Audit(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    identity: Mapped[str] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(256))
    timestamp: Mapped[float] = mapped_column(Float, default=time.time, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
