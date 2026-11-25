from typing import Literal

from pydantic import BaseModel, Field

from ..schemas import ArtifactFile
from .schemas import YAMLFile


class CustomTestCreate(YAMLFile):
    filename: str = Field(
        default="custom.yaml", max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*\.ya?ml$"
    )
    files: list[ArtifactFile] = Field(default_factory=list, max_length=127)


class SubmittedTest(BaseModel):
    guid: str
    name: str
    technique: str
    content_sha256: str


class SubmittedFile(BaseModel):
    path: str
    size: int
    sha256: str


class CustomTestReceipt(BaseModel):
    id: str
    status: Literal["submitted"] = "submitted"
    source: Literal["custom"] = "custom"
    revision: str
    revision_kind: Literal["content"] = "content"
    submitted_by: str
    created_at: float
    tests: list[SubmittedTest]
    files: list[SubmittedFile]
    replayed: bool
    next_step: str = "Review and approve the submitted tests in Test Catalog before execution."
