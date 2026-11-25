from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OptionalTestingReason(Strict):
    reason: str = Field(default="", max_length=2000)

    @field_validator("reason", mode="before")
    @classmethod
    def optional_reason(cls, value):
        return "" if value is None else value.strip() if isinstance(value, str) else value


class RunRequest(OptionalTestingReason):
    atomic_guid: UUID
    actor_id: UUID
    execution_profile_id: UUID
    action: Literal["execute", "check"] = "execute"
    timeout_seconds: int = Field(default=120, ge=10, le=600)


class Reason(Strict):
    reason: str = Field(min_length=8, max_length=2000)


class QueuePreviewRequest(Strict):
    execution_profile_id: UUID
    atomic_guids: list[UUID] = Field(min_length=1, max_length=500)
    timeout_seconds: int = Field(default=120, ge=10, le=600)

    @field_validator("atomic_guids")
    @classmethod
    def unique_tests(cls, values: list[UUID]) -> list[UUID]:
        return list(dict.fromkeys(values))


class QueueRequest(QueuePreviewRequest, OptionalTestingReason):
    preview_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    name: str = Field(default="Selected catalog tests", min_length=1, max_length=128)
    failure_policy: Literal["pause", "continue"] = "continue"


class Reconciliation(Reason):
    workspace_removed: bool = False


class RetireActorRequest(Strict):
    hostname: str = Field(min_length=1, max_length=128)
    reason: str | None = Field(default="", max_length=2000)

    @field_validator("reason")
    @classmethod
    def optional_reason(cls, value: str | None) -> str:
        return (value or "").strip()


class EnrollmentRequest(Strict):
    token: str = Field(min_length=32, max_length=256)
    hostname: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")
    agent_version: str = Field(max_length=40)
    os_version: str = Field(max_length=128)
    os: Literal["windows", "linux"] = "windows"


class EnrollmentTokenRequest(Strict):
    hostname: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")
    os: Literal["windows", "linux"] = "windows"


class ProfileRequest(Strict):
    profile_key: Literal["standard-user", "local-admin"]
    display_name: str = Field(min_length=1, max_length=128)
    account: str = Field(min_length=1, max_length=128)
    expected_sid: str = Field(pattern=r"^(?:S-1-5-(?:\d+-)*\d+|uid:(?:0|[1-9]\d{0,9}))$")
    privilege: Literal["standard", "elevated"]


class ArtifactFile(Strict):
    path: str = Field(min_length=1, max_length=240)
    content_base64: str = Field(max_length=22_369_624)


class ArtifactPreparation(Strict):
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    asset_paths: list[str] = Field(default_factory=list, max_length=127)
    files: list[ArtifactFile] = Field(default_factory=list, max_length=127)


class WorkspaceReceipt(Strict):
    attempt_id: UUID
    fence: str = Field(min_length=32, max_length=128)
    artifact_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["removing", "purged", "purge_failed"]


class Heartbeat(Strict):
    workspace_residue: bool = False
    delivery_mode: Literal["checkout", "on_demand"] = "checkout"
    artifact_protocol: Literal[0, 1] = 0
    catalog_sync_protocol: Literal[0, 1] = 0
    catalog_config_hash: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")
    catalog_health: Literal["unknown", "ready", "missing", "mismatch", "dirty", "unavailable"] = "unknown"
    profile_sync_protocol: Literal[0, 1] = 0
    profile_config_hash: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")
    hostname: str = Field(max_length=128)
    agent_version: str = Field(max_length=40)
    os_version: str = Field(max_length=128)
    revision: str = Field(max_length=128)
    profiles: dict[str, bool] = Field(max_length=16)
    health: Literal["healthy", "degraded", "recovering"]
    active_execution_id: UUID | None = None
    os: Literal["windows", "linux"] = "windows"


class LeaseProof(Strict):
    attempt_id: UUID
    fence: str = Field(min_length=32, max_length=128)


class Identity(Strict):
    platform: Literal["windows"] = "windows"
    expected_profile_id: UUID
    expected_account_sid: str = Field(max_length=184)
    actual_account_sid: str = Field(max_length=184)
    actual_account_name: str = Field(max_length=256)
    logon_session_id: str | None = Field(default=None, max_length=128)
    elevated: bool
    admin_member: bool
    admin_enabled: bool = False
    enabled_privileges: list[str] = Field(default_factory=list, max_length=128)
    integrity_level: Literal["low", "medium", "high", "system"]
    process_id: int = Field(ge=1)
    verified: bool


class LinuxIdentity(Strict):
    platform: Literal["linux"]
    expected_profile_id: UUID
    expected_account_sid: str = Field(max_length=184)
    actual_account_sid: str = Field(max_length=184)
    actual_account_name: str = Field(max_length=256)
    uid: int = Field(ge=0)
    euid: int = Field(ge=0)
    gid: int = Field(ge=0)
    egid: int = Field(ge=0)
    groups: list[int] = Field(max_length=256)
    capabilities: str = Field(pattern=r"^[a-f0-9]{16}$")
    permitted_capabilities: str = Field(pattern=r"^[a-f0-9]{16}$")
    ambient_capabilities: str = Field(pattern=r"^[a-f0-9]{16}$")
    bounding_capabilities: str = Field(pattern=r"^[a-f0-9]{16}$")
    no_new_privileges: bool
    elevated: bool
    process_id: int = Field(ge=1)
    verified: bool


class Result(LeaseProof):
    status: Literal["succeeded", "failed", "timed_out", "cancelled", "inconclusive"]
    identity: Identity | LinuxIdentity | None = None
    exit_code: int | None = None
    stdout: str = Field(default="", max_length=65536)
    stderr: str = Field(default="", max_length=65536)
    prerequisites: dict[str, Any] | None = None
    started_at: float
    finished_at: float
    simulated: bool = False


class TestReview(Strict):
    asset_paths: list[str] | None = Field(default=None, max_length=127)
    files: list[ArtifactFile] = Field(default_factory=list, max_length=127)
    artifact_digest: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_revision: str = Field(min_length=1, max_length=128)
    allowed_profiles: list[Literal["standard-user", "local-admin"]] = Field(min_length=1)
    risk_level: Literal["low", "medium", "high"]


class RunResponse(BaseModel):
    preparation: dict[str, Any] = Field(default_factory=dict)
    execution_artifact: dict[str, Any] | None = None
    workspace_status: str = "not_required"
    batch_id: str | None = None
    queue_position: int = 0
    run_id: str
    status: str
    actor_id: str
    execution_profile_id: str
    approval_required: bool = True
    snapshot: dict[str, Any]
    result: dict[str, Any] | None
    created_at: float
    updated_at: float
    requested_by: str
    reason: str
    action: str
    parent_id: str | None
    cancel_requested: bool
    cleanup_status: str = "not_requested"
    events: list[dict[str, Any]] = []
    approved_by: str | None = None
    authorization_source: Literal["catalog", "per_run"] | None = None


class ProfileResponse(BaseModel):
    id: str
    actor_id: str
    profile_key: str
    display_name: str
    account: str
    expected_sid: str
    privilege: str
    logon_type: str
    enabled: bool
    healthy: bool


class ActorDeletionResponse(BaseModel):
    id: str
    hostname: str
    deleted: Literal[True] = True
    deleted_at: float
    deleted_by: str
    reason: str


class ActorResponse(BaseModel):
    workspace_status: str = "not_required"
    delivery_mode: str = "checkout"
    artifact_protocol: int = 0
    catalog: dict[str, Any] = Field(default_factory=dict)
    retired_at: float | None = None
    retired_by: str | None = None
    retirement_reason: str | None = None
    profile_sync: dict[str, Any] = Field(default_factory=dict)
    registration_state: str
    id: str
    hostname: str
    os: str
    os_version: str
    agent_version: str
    revision: str
    enabled: bool
    online: bool
    last_heartbeat: float
    health: str
    active_job: str | None
    simulated: bool
    profiles: list[ProfileResponse]


class TestResponse(BaseModel):
    file_plan: dict[str, Any] | None = None
    artifact: dict[str, Any] | None = None
    artifact_approved: bool = False
    catalog_source: str
    source_path: str
    active: bool
    execution_ready: bool
    guid: str
    name: str
    technique: str
    revision: str
    content_sha256: str
    definition: dict[str, Any]
    approved: bool
    risk_level: str
    allowed_profiles: list[str]
    simulated: bool


class Paged[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int
