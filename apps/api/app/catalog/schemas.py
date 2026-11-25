from typing import Any, Literal

from pydantic import Field, field_validator

from ..schemas import Strict


class GitHubSync(Strict):
    ref: str = Field(
        default="master", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$"
    )

    @field_validator("ref")
    @classmethod
    def safe_ref(cls, value):
        if ".." in value or "//" in value or value.endswith("/"):
            raise ValueError("Invalid GitHub reference")
        return value


class YAMLFile(Strict):
    filename: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*\.ya?ml$")
    content: str = Field(min_length=1, max_length=1_000_000)


class YAMLUpload(Strict):
    files: list[YAMLFile] = Field(min_length=1, max_length=50)
    source_revision: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")


class ConfirmImport(Strict):
    preview_token: str = Field(pattern=r"^[a-f0-9]{64}$")
    replace_conflicts: bool = False


class ImportStatus(Strict):
    id: str
    source: Literal["github", "upload"]
    ref: str
    revision: str
    status: Literal["fetching", "ready", "imported", "failed"]
    created_by: str
    created_at: float
    updated_at: float
    applied_by: str | None
    error: str | None
    test_count: int
    file_count: int
    pinned: bool


class ImportPreview(ImportStatus):
    counts: dict[str, int]
    changes: list[dict[str, Any]]
    preview_token: str
    total: int
    limit: int
    offset: int
