"""Human administrator UI for explicitly scoped execution permissions."""

import hashlib
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import Literal
from uuid import UUID

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy.orm import Session

from ..auth import Principal, human
from ..catalog.parser import approved, execution_platforms
from ..db import session
from ..errors import fail
from ..models import Actor, AtomicTest, Profile
from ..services.common import audit, fingerprint

router = APIRouter(prefix="/api/v1/execution-access")
Action = Literal["execute", "check", "cleanup", "approve"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Scope(Strict):
    actions: list[Action] = Field(min_length=1, max_length=4)
    actors: list[UUID] = Field(min_length=1, max_length=64)
    profiles: list[UUID] = Field(min_length=1, max_length=64)
    tests: list[UUID] = Field(min_length=1, max_length=256)
    risks: list[Literal["low", "medium", "high"]] = Field(min_length=1, max_length=3)


class Policy(Strict):
    subjects: dict[str, list[Scope]] = Field(default_factory=dict, max_length=256)


class Preview(Strict):
    operation: Literal["grant", "revoke"]
    version: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject: str | None = Field(default=None, min_length=1, max_length=256)
    actor_id: UUID | None = None
    profile_id: UUID | None = None
    test_guid: UUID | None = None
    actions: list[Action] = Field(default_factory=list, max_length=4)
    grant_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("subject")
    @classmethod
    def exact_subject(cls, value):
        if value is not None and (value != value.strip() or "*" in value or any(ord(c) < 32 for c in value)):
            raise ValueError("Use an exact OIDC subject without wildcards or control characters")
        return value

    @model_validator(mode="after")
    def operation_fields(self):
        if self.operation == "grant":
            if (
                not all([self.subject, self.actor_id, self.profile_id, self.test_guid, self.actions])
                or self.grant_id
            ):
                raise ValueError("A grant requires an exact subject, actor, profile, test and actions")
            self.actions = sorted(set(self.actions))
        elif not self.grant_id or any(
            [self.subject, self.actor_id, self.profile_id, self.test_guid, self.actions]
        ):
            raise ValueError("Revocation requires only the existing grant ID")
        return self


class Apply(Strict):
    preview_token: str = Field(min_length=32, max_length=128)
    confirmed: Literal[True]
    reason: str = Field(min_length=10, max_length=1000)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        value = value.strip()
        if len(value) < 10:
            raise ValueError("Describe the reason for this permission change")
        return value


def policy_path(settings):
    if (
        settings.approval_mode != "per_run"
        or settings.mode != "real"
        or settings.dev_auth
        or not settings.policy_file
    ):
        return None
    return Path(settings.policy_file)


def read_policy(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_000_000:
        fail("policy_unavailable", "The configured execution policy is unavailable for editing", 503)
    try:
        raw = path.read_bytes()
    except OSError:
        fail("policy_unavailable", "The configured execution policy could not be read", 503)
    try:
        policy = Policy.model_validate(yaml.safe_load(raw))
    except (ValueError, yaml.YAMLError, ValidationError):
        fail("policy_invalid", "The configured execution policy must be repaired before editing", 503)
    return policy.model_dump(mode="json"), hashlib.sha256(raw).hexdigest()


def entries(policy):
    return [
        {"id": fingerprint({"subject": subject, **grant}), "subject": subject, **grant}
        for subject, grants in policy["subjects"].items()
        for grant in grants
    ]


def validated_change(db, policy, payload: Preview):
    current = entries(policy)
    if payload.operation == "revoke":
        grant = next((grant for grant in current if grant["id"] == payload.grant_id), None)
        if not grant:
            fail("grant_not_found", "That permission grant no longer exists", 409)
        return {"grant": grant, "labels": {}, "test_binding": None}
    actor = db.get(Actor, str(payload.actor_id))
    profile = db.get(Profile, str(payload.profile_id))
    test = db.get(AtomicTest, str(payload.test_guid))
    if (
        not actor
        or actor.registration_state == "retired"
        or not actor.enabled
        or actor.simulated
        or not profile
        or profile.actor_id != actor.id
        or not profile.enabled
    ):
        fail("invalid_access_scope", "Select an enabled real actor and its registered execution profile", 422)
    review = approved(db, test) if test else None
    if not test or test.simulated or not review:
        fail("test_unapproved", "Select a currently approved real test definition", 422)
    if (
        actor.os not in execution_platforms(test.definition)
        or actor.os not in review.allowed_platforms
        or profile.profile_key not in review.allowed_profiles
    ):
        fail("incompatible_profile", "This test is not approved for the selected platform and profile", 422)
    if (
        test.definition.get("executor", {}).get("elevation_required", False)
        and profile.privilege != "elevated"
    ):
        fail("elevation_required", "This test requires an elevated execution profile", 422)
    grant = {
        "subject": payload.subject,
        "actions": payload.actions,
        "actors": [actor.id],
        "profiles": [profile.id],
        "tests": [test.guid],
        "risks": [review.risk_level],
    }
    grant["id"] = fingerprint(grant)
    if any(item["id"] == grant["id"] for item in current):
        fail("grant_exists", "This exact execution permission already exists", 409)
    return {
        "grant": grant,
        "labels": {
            "actor": actor.hostname,
            "profile": profile.display_name,
            "account": profile.account,
            "identity": profile.expected_sid,
            "test": test.name,
            "technique": test.technique,
            "privilege": profile.privilege,
        },
        "test_binding": {"revision": test.revision, "hash": test.content_hash, "risk": review.risk_level},
    }


def replace_policy(path, policy):
    if (
        path.is_symlink()
        or path.parent.is_symlink()
        or not path.parent.is_dir()
        or path.parent.stat().st_mode & 0o022
    ):
        fail("policy_unavailable", "The policy directory must be protected from other users' writes", 503)
    descriptor, name = tempfile.mkstemp(prefix=".execution-access-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(yaml.safe_dump(policy, sort_keys=False))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


@router.get("")
def list_access(request: Request, p: Principal = Depends(human)):
    p.require("administrator")
    path = policy_path(request.app.state.settings)
    if path is None:
        if request.app.state.settings.approval_mode == "catalog":
            return {
                "configured": False,
                "version": None,
                "grants": [],
                "message": "Catalog approval authorizes operator requests on enrolled, compatible hosts. No separate execution-access grants are needed.",
            }
        return {
            "configured": False,
            "version": None,
            "grants": [],
            "message": "Execution access editing requires a real deployment with a configured policy. Simulation does not use these grants.",
        }
    policy, version = read_policy(path)
    return {
        "configured": True,
        "version": version,
        "grants": entries(policy),
        "message": "Roles are still required. Grants scope future requests and approvals; existing runs retain their own approvals.",
    }


@router.post("/preview")
def preview_access(
    data: Preview, request: Request, p: Principal = Depends(human), db: Session = Depends(session)
):
    p.require("administrator")
    path = policy_path(request.app.state.settings)
    if path is None:
        fail("policy_not_configured", "Configure a real execution policy before managing access", 409)
    with request.app.state.execution_access_lock:
        policy, version = read_policy(path)
        if version != data.version:
            fail("policy_changed", "Execution permissions changed. Reload and review again", 409)
        change = validated_change(db, policy, data)
        pending = request.app.state.execution_access_previews
        now = time.time()
        for key in list(pending):
            if pending[key]["expires_at"] <= now:
                del pending[key]
        if len(pending) >= 128:
            fail("preview_limit", "Too many permission reviews are pending; retry shortly", 429)
        token = secrets.token_urlsafe(32)
        expires = now + 300
        pending[token] = {
            "subject": p.subject,
            "expires_at": expires,
            "payload": data.model_dump(mode="json"),
            "change": change,
        }
        return {
            "preview_token": token,
            "expires_at": expires,
            "operation": data.operation,
            "version": version,
            **change,
        }


@router.post("/apply")
def apply_access(
    data: Apply, request: Request, p: Principal = Depends(human), db: Session = Depends(session)
):
    p.require("administrator")
    path = policy_path(request.app.state.settings)
    if path is None:
        fail("policy_not_configured", "Configure a real execution policy before managing access", 409)
    write_error = None
    with request.app.state.execution_access_lock:
        pending = request.app.state.execution_access_previews.get(data.preview_token)
        if not pending or pending["subject"] != p.subject or pending["expires_at"] <= time.time():
            fail("preview_expired", "This permission review expired or belongs to another administrator", 409)
        payload = Preview.model_validate(pending["payload"])
        policy, version = read_policy(path)
        if payload.version != version:
            fail("policy_changed", "Execution permissions changed. Reload and review again", 409)
        change = validated_change(db, policy, payload)
        if fingerprint(change) != fingerprint(pending["change"]):
            fail("scope_changed", "The reviewed actor, profile or test changed. Review again", 409)
        grant = change["grant"]
        if payload.operation == "grant":
            scope = {key: value for key, value in grant.items() if key not in {"id", "subject"}}
            policy["subjects"].setdefault(grant["subject"], []).append(scope)
        else:
            scopes = policy["subjects"][grant["subject"]]
            policy["subjects"][grant["subject"]] = [
                scope
                for scope in scopes
                if fingerprint({"subject": grant["subject"], **scope}) != grant["id"]
            ]
            if not policy["subjects"][grant["subject"]]:
                del policy["subjects"][grant["subject"]]
        # Validate the full result before any file write. Commit an audit intent first
        # because the YAML file and SQLite transaction cannot commit atomically.
        Policy.model_validate(policy)
        audit(
            db,
            p.subject,
            "execution_access.intent",
            grant["id"],
            operation=payload.operation,
            reason=data.reason,
            grant=grant,
            previous_version=version,
        )
        db.commit()
        request.app.state.execution_access_previews.pop(data.preview_token, None)
        try:
            replace_policy(path, policy)
        except (OSError, HTTPException) as error:
            write_error = error
        if write_error is None:
            _, updated_version = read_policy(path)
    # Do not reacquire a SQLite write transaction while holding the policy lock:
    # another request may already hold that transaction while waiting for the lock.
    if write_error is not None:
        audit(db, p.subject, "execution_access.write_failed", grant["id"], operation=payload.operation)
        db.commit()
        if isinstance(write_error, HTTPException):
            raise write_error
        fail(
            "policy_write_failed",
            "The policy could not be saved. Reload execution access to check the current state",
            503,
        )
    audit(
        db,
        p.subject,
        "execution_access.applied",
        grant["id"],
        operation=payload.operation,
        version=updated_version,
    )
    return {
        "configured": True,
        "version": updated_version,
        "grants": entries(policy),
        "message": "Execution permissions updated. No execution was requested or approved.",
    }
