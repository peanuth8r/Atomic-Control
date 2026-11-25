import ipaddress
import secrets
import time
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..agents.package import build_package, public_ca
from ..agents.schemas import AgentPackageRequest, RegisterActor
from ..auth import Principal
from ..catalog.validation import pinned
from ..db import session
from ..errors import fail
from ..models import Actor, AtomicTest, CustomTestSubmission, Enrollment, Lease, Profile, Revision
from ..services.actor_status import require_current_actor
from ..services.agent_settings import enrollment_seconds
from ..services.catalog_deployments import applying as catalog_applying
from ..services.common import audit, digest
from .api import actor_view
from .catalog import administrator

router = APIRouter(prefix="/api/v1", tags=["Agent packages"])


@router.post("/actors", status_code=201)
def register_actor(
    data: RegisterActor,
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(administrator),
):
    existing = db.scalar(
        select(Actor).where(func.lower(Actor.hostname) == data.hostname.lower()).with_for_update()
    )
    if existing:
        require_current_actor(existing)
        fail("actor_exists", "An actor with that hostname is already registered")
    actor = Actor(
        hostname=data.hostname,
        os=data.os,
        simulated=False,
        registration_state="pending_enrollment",
        health="pending_enrollment",
    )
    db.add(actor)
    db.flush()
    audit(db, p.subject, "actor.registered", actor.id, hostname=actor.hostname)
    return actor_view(db, actor, request.app.state.settings)


@router.get("/agents/package-options")
def options(request: Request, db: Session = Depends(session), p: Principal = Depends(administrator)):
    settings = request.app.state.settings
    ca = public_ca(settings)
    return {
        "default_delivery_mode": "on_demand",
        "delivery_modes": ["on_demand", "checkout"],
        "mode": settings.mode,
        "api_url": settings.public_url,
        "enrollment_available": True,
        "revisions": [
            r.id
            for r in db.scalars(select(Revision).order_by(Revision.imported_at.desc()))
            if pinned(r.id)
            and not db.scalar(select(CustomTestSubmission.id).where(CustomTestSubmission.revision == r.id))
        ],
        "token_lifetime_seconds": enrollment_seconds(db),
        "format": "zip",
        "platforms": ["windows", "linux"],
        "requires_python": "3.12+",
        "public_ca": ca[1] if ca else None,
    }


@router.post(
    "/actors/{actor_id}/agent-package",
    response_class=Response,
    responses={
        200: {
            "description": "Actor-specific Windows or Linux agent ZIP",
            "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}},
        }
    },
)
def download(
    actor_id: UUID,
    data: AgentPackageRequest,
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(administrator),
):
    settings = request.app.state.settings
    actor = db.get(Actor, str(actor_id), with_for_update=True)
    if not actor:
        fail("not_found", "Actor does not exist", 404)
    require_current_actor(actor)
    if data.catalog_revision and not db.get(Revision, data.catalog_revision):
        fail("unknown_catalog_revision", "Choose an imported catalog revision or configure it later", 422)
    token, expires = None, None
    token_seconds = enrollment_seconds(db)
    if data.include_enrollment:
        if actor.simulated:
            fail(
                "actor_unavailable",
                "Legacy fixture actors cannot receive enrollment packages",
                409,
            )
        if data.api_url != settings.public_url.rstrip("/"):
            fail(
                "control_plane_url_mismatch",
                "Enrollment packages must use the configured public HTTPS control-plane URL",
                422,
            )
        hostname = urlsplit(data.api_url).hostname or ""
        loopback = hostname.lower() in {"localhost", "localhost.localdomain"} or hostname.lower().endswith(
            (".localhost", ".invalid")
        )
        try:
            loopback = (
                loopback
                or ipaddress.ip_address(hostname).is_loopback
                or ipaddress.ip_address(hostname).is_unspecified
            )
        except ValueError:
            pass
        if loopback:
            fail(
                "unreachable_agent_url",
                "Use the HTTPS control-plane hostname reachable from the agent host",
                422,
            )
        if db.get(Lease, actor.id) or catalog_applying(db, actor):
            fail(
                "actor_busy",
                "Resolve active or inconclusive work before generating a replacement enrollment package",
            )
        if actor.registration_state == "enrolled" and actor.enabled:
            fail(
                "actor_must_be_disabled",
                "Disable this enrolled actor before replacing its identity, or download a configuration-only package",
            )
        for previous in db.scalars(
            select(Enrollment).where(Enrollment.actor_id == actor.id, Enrollment.used.is_(False))
        ):
            previous.used = True
        token, expires = secrets.token_urlsafe(48), time.time() + token_seconds
        db.add(
            Enrollment(
                actor_id=actor.id,
                os=actor.os,
                digest=digest(token),
                hostname=actor.hostname,
                expires_at=expires,
            )
        )
    profiles = db.scalars(
        select(Profile).where(Profile.actor_id == actor.id).order_by(Profile.profile_key)
    ).all()
    catalog = None
    if actor.os == "windows" and data.catalog_revision:
        tests = db.scalars(
            select(AtomicTest)
            .where(
                AtomicTest.revision == data.catalog_revision,
                AtomicTest.active.is_(True),
                AtomicTest.simulated.is_(False),
            )
            .order_by(AtomicTest.guid)
        ).all()
        if not tests:
            fail("empty_catalog", "Select a revision containing active imported definitions", 422)
        catalog = {
            "protocol": 1,
            "actor_id": actor.id,
            "hostname": actor.hostname,
            "source": "redcanaryco/atomic-red-team",
            "revision": data.catalog_revision,
            "tests": [{"guid": t.guid, "technique": t.technique, "sha256": t.content_hash} for t in tests],
        }
    content, filename = build_package(
        actor, profiles, data, settings, token, expires, catalog=catalog, enrollment_seconds=token_seconds
    )
    checksum = __import__("hashlib").sha256(content).hexdigest()
    audit(
        db,
        p.subject,
        "agent.package-generated",
        actor.id,
        mode="enrollment" if token else "configuration_only",
        sha256=checksum,
        enrollment_expires_at=expires,
    )
    db.commit()
    # Commit the enrollment digest/audit before sending the secret-bearing ZIP.
    # Never return any part of the package through JSON/logging or persist the archive on the server.
    return Response(
        content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Package-SHA256": checksum,
            "X-Package-Mode": "enrollment" if token else "configuration_only",
            "X-Enrollment-Expires-At": str(expires or ""),
        },
    )
