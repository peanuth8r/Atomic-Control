import time
from pathlib import Path
from typing import Literal
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, Request
from pydantic import Field
from sqlalchemy.orm import Session

from apps.agent.catalog_config import ISSUER

from ..auth import Principal, agent, human
from ..db import session
from ..errors import fail
from ..models import Actor, CatalogDeployment, Lease
from ..schemas import Strict
from ..services import catalog_deployments as deployments
from ..services.actor_status import require_current_actor
from ..services.common import audit
from ..services.profile_sync import latest as latest_profiles
from ..services.token_time import token_issued_at

router = APIRouter(prefix="/api/v1")


class Install(Strict):
    revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmed: Literal[True]


class Receipt(Strict):
    generation: int = Field(ge=1)
    payload_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["applied", "failed"]
    observed_revision: str = Field(pattern=r"^(?:[a-f0-9]{40})?$")
    error: Literal[
        "",
        "fetch_failed",
        "verification_failed",
        "insufficient_space",
        "apply_failed",
        "interrupted",
        "configuration_changed",
    ] = ""


def linux(actor):
    require_current_actor(actor)
    if actor.delivery_mode == "on_demand":
        fail(
            "catalog_not_required",
            "On-demand actors receive approved files per job; no host catalog installation is needed",
            409,
        )
    if actor.os != "linux" or actor.simulated:
        fail("unsupported_catalog_install", "Managed catalog installation requires a real Linux actor", 422)


@router.get("/actors/{actor_id}/catalog-options")
def options(actor_id: UUID, db: Session = Depends(session), p: Principal = Depends(human)):
    p.require("administrator")
    actor = db.get(Actor, str(actor_id))
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    linux(actor)
    return {"revisions": deployments.options(db, actor), **deployments.view(db, actor)}


@router.post("/actors/{actor_id}/catalog-install")
def install(actor_id: UUID, data: Install, db: Session = Depends(session), p: Principal = Depends(human)):
    p.require("administrator")
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    linux(actor)
    if actor.catalog_sync_protocol != 1:
        fail(
            "agent_upgrade_required", "Update the agent with managed catalog installation enabled first", 409
        )
    deployments.queue(db, actor, data.revision, data.manifest_hash, p.subject)
    return deployments.view(db, actor)


@router.post("/agents/catalog-install/poll")
def poll(request: Request, actor: Actor = Depends(agent), db: Session = Depends(session)):
    linux(actor)
    if actor.catalog_sync_protocol != 1:
        fail("agent_upgrade_required", "Managed catalog installation is not enabled", 409)
    item = deployments.latest(db, actor)
    if not item or item.status not in {"pending", "applying"}:
        return {"manifest": None}
    profiles = latest_profiles(db, actor)
    if db.get(Lease, actor.id) is not None or (
        item.status == "pending" and profiles and profiles.status in {"pending", "applying"}
    ):
        return {"manifest": None, "waiting_for_idle": True}
    now = time.time()
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": actor.id,
            "iat": token_issued_at(now),
            "exp": now + 180,
            "type": "catalog-install-v1",
            "jti": item.id,
            "generation": item.generation,
            "payload": item.payload,
            "payload_hash": item.payload_hash,
        },
        Path(request.app.state.settings.signing_key_file).read_text(),
        algorithm="RS256",
    )
    if item.status == "pending":
        item.status, item.updated_at = "applying", now
    return {"manifest": token}


@router.post("/agents/catalog-install/{deployment_id}/result")
def result(deployment_id: UUID, data: Receipt, actor: Actor = Depends(agent), db: Session = Depends(session)):
    item = db.get(CatalogDeployment, str(deployment_id))
    if not item or item.actor_id != actor.id:
        fail("not_found", "Catalog installation does not exist", 404)
    if (
        deployments.latest(db, actor).id != item.id
        or item.generation != data.generation
        or item.payload_hash != data.payload_hash
    ):
        fail("stale_configuration", "A newer catalog installation exists", 409)
    if data.status == "applied" and (data.observed_revision != item.revision or data.error):
        fail("invalid_result", "Successful installation must verify the exact requested revision", 422)
    if data.status == "failed" and not data.error:
        fail("invalid_result", "Failed installation requires an error code", 422)
    if item.status in {"applied", "failed"}:
        if (item.status, item.observed_revision, item.error) != (
            data.status,
            data.observed_revision,
            data.error,
        ):
            fail("conflicting_result", "Catalog installation already has a different result", 409)
        return {"accepted": True, "status": item.status}
    if item.status != "applying" or db.get(Lease, actor.id) is not None:
        fail("invalid_state", "Catalog installation must be idle and applying", 409)
    item.status, item.error, item.observed_revision, item.updated_at = (
        data.status,
        data.error,
        data.observed_revision,
        time.time(),
    )
    actor.revision = item.revision if data.status == "applied" else ""
    actor.catalog_health = "ready" if data.status == "applied" else "unavailable"
    audit(
        db,
        "agent:" + actor.id,
        "catalog_deployment." + item.status,
        actor.id,
        revision=item.revision,
        generation=item.generation,
        error=item.error,
    )
    return {"accepted": True, "status": item.status}
