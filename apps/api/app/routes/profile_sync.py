"""Signed Linux and Windows profiles delivered over the outbound agent channel."""

import time
from pathlib import Path
from typing import Literal
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, Request
from pydantic import Field
from sqlalchemy.orm import Session

from apps.agent.identity_validation import IdentityMismatch
from apps.agent.identity_validation import validate_identity as validate_windows
from apps.agent.linux.identity import validate_identity as validate_linux
from apps.agent.profile_config import ISSUER

from ..auth import Principal, agent, human
from ..db import session
from ..errors import fail
from ..models import Actor, Lease, Profile, ProfileSync
from ..schemas import Identity, LinuxIdentity, Strict
from ..services.actor_status import require_current_actor
from ..services.catalog_deployments import applying as catalog_applying
from ..services.common import audit, fingerprint
from ..services.profile_sync import delete_profile, latest, queue, view
from ..services.token_time import token_issued_at

router = APIRouter(prefix="/api/v1")


@router.delete("/actors/{actor_id}/profiles/{profile_id}")
def remove_profile(
    actor_id: UUID, profile_id: UUID, db: Session = Depends(session), p: Principal = Depends(human)
):
    p.require("administrator")
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if actor is None:
        fail("not_found", "Actor does not exist", 404)
    return delete_profile(db, actor, profile_id, p.subject)


class Validation(Strict):
    healthy: bool
    identity: Identity | LinuxIdentity | None = None
    error: Literal[
        "",
        "disabled",
        "account_missing",
        "identity_mismatch",
        "probe_failed",
        "task_missing",
        "task_mismatch",
    ] = ""


class SyncResult(Strict):
    generation: int = Field(ge=1)
    payload_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    results: dict[str, Validation] = Field(default_factory=dict, max_length=2)
    error: Literal["", "configuration_rejected", "apply_failed"] = ""


@router.post("/actors/{actor_id}/profile-sync")
def request_sync(
    actor_id: UUID, request: Request, db: Session = Depends(session), p: Principal = Depends(human)
):
    p.require("administrator")
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    require_current_actor(actor)
    if actor.os not in {"linux", "windows"} or actor.simulated or request.app.state.settings.mode != "real":
        fail("unsupported_sync", "Managed profiles require a real Linux or Windows agent", 422)
    if actor.profile_sync_protocol != 1:
        fail("agent_upgrade_required", "Update the agent to enable automatic profile updates", 409)
    queue(db, actor, p.subject, retry=True)
    return view(db, actor)


@router.post("/agents/profile-sync/poll")
def poll(request: Request, actor: Actor = Depends(agent), db: Session = Depends(session)):
    if actor.os not in {"linux", "windows"} or actor.profile_sync_protocol != 1 or actor.simulated:
        fail("unsupported_sync", "Agent has not enabled automatic profile updates", 409)
    item = latest(db, actor)
    if not item or item.status not in {"pending", "applying"}:
        return {"manifest": None}
    if db.get(Lease, actor.id) or catalog_applying(db, actor):
        return {"manifest": None, "waiting_for_idle": True}
    now = time.time()
    grant = jwt.encode(
        {
            "iss": ISSUER,
            "aud": actor.id,
            "iat": token_issued_at(now),
            "exp": now + 180,
            "type": "profile-sync-v1",
            "jti": item.id,
            "generation": item.generation,
            "payload_hash": item.payload_hash,
            "payload": item.payload,
        },
        Path(request.app.state.settings.signing_key_file).read_text(),
        algorithm="RS256",
    )
    if item.status == "pending":
        item.status, item.updated_at = "applying", now
    return {"manifest": grant}


@router.post("/agents/profile-sync/{sync_id}/result")
def result(sync_id: UUID, data: SyncResult, actor: Actor = Depends(agent), db: Session = Depends(session)):
    item = db.get(ProfileSync, str(sync_id))
    if not item or item.actor_id != actor.id:
        fail("not_found", "Profile synchronization does not exist", 404)
    if (
        latest(db, actor).id != item.id
        or item.generation != data.generation
        or item.payload_hash != data.payload_hash
    ):
        fail("stale_configuration", "A newer profile configuration exists", 409)
    value = data.model_dump(mode="json")
    if item.status in {"applied", "validation_failed", "failed"}:
        if fingerprint(item.results) != fingerprint(value["results"]) or item.error != data.error:
            fail("conflicting_result", "Profile configuration already has a different result", 409)
        return {"accepted": True, "status": item.status}
    if item.status != "applying" or db.get(Lease, actor.id) is not None:
        fail("invalid_state", "Profile synchronization is not idle and applying", 409)
    profiles = {p["id"]: p for p in item.payload["profiles"]}
    if not data.error and set(data.results) != set(profiles):
        fail("invalid_result", "Every configured profile requires a validation result", 422)
    if set(data.results) - set(profiles):
        fail("invalid_result", "Result contains an unknown profile", 422)
    for key, validation in data.results.items():
        profile = profiles[key]
        if validation.healthy:
            evidence = validation.identity
            if (
                not profile["enabled"]
                or not evidence
                or str(evidence.expected_profile_id) != key
                or evidence.expected_account_sid != profile["expected_sid"]
                or not evidence.verified
                or validation.error
            ):
                fail("invalid_identity", "Profile identity binding is invalid", 422)
            try:
                if (evidence.platform == "linux") != (actor.os == "linux"):
                    raise ValueError("Identity evidence belongs to another platform")
                validator = validate_linux if actor.os == "linux" else validate_windows
                validator(evidence.model_dump(mode="json"), profile)
            except (ValueError, KeyError, IdentityMismatch):
                fail("invalid_identity", "Kernel identity does not match the configured profile", 422)
    for key in profiles:
        registered = db.get(Profile, key)
        if registered is None:
            fail("stale_configuration", "Profile was removed", 409)
        registered.healthy = not data.error and data.results[key].healthy
    item.results, item.error = value["results"], data.error
    item.status = (
        "failed"
        if data.error
        else (
            "validation_failed"
            if any(p["enabled"] and not data.results[k].healthy for k, p in profiles.items())
            else "applied"
        )
    )
    item.updated_at = time.time()
    if not data.error:
        actor.profile_config_hash = item.payload_hash
    audit(db, "agent:" + actor.id, "profile_sync." + item.status, actor.id, generation=item.generation)
    return {"accepted": True, "status": item.status}
