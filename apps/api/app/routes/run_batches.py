from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import Principal, human, viewer
from ..db import session
from ..errors import fail
from ..models import RunBatch
from ..schemas import QueuePreviewRequest, QueueRequest
from ..services import run_batches as service

router = APIRouter(prefix="/api/v1")


def operator(principal, scope):
    principal.require("operator")
    if principal.mcp and scope not in principal.scopes:
        fail("insufficient_scope", "Caller lacks the queue action scope", 403)


def need(db, batch_id):
    batch = db.get(RunBatch, str(batch_id))
    if not batch:
        fail("not_found", "Batch does not exist", 404)
    return batch


@router.post("/actors/{actor_id}/queue/preview")
def preview(
    actor_id: UUID,
    data: QueuePreviewRequest,
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    operator(p, "atomic:read")
    actor = service.actor_for_write(db, actor_id)
    return service.preview(db, request.app.state.settings, p, actor, data)


@router.post("/actors/{actor_id}/queue", status_code=201)
def submit(
    actor_id: UUID,
    data: QueueRequest,
    request: Request,
    idempotency_key: str = Header(),
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    operator(p, "atomic:request")
    return service.view(
        db, service.submit(db, request.app.state.settings, p, actor_id, data, idempotency_key)
    )


@router.get("/actors/{actor_id}/queue")
def queue(
    actor_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(session),
    p: Principal = Depends(viewer),
):
    batches = db.scalars(
        select(RunBatch)
        .where(RunBatch.actor_id == str(actor_id))
        .order_by(RunBatch.created_at.desc(), RunBatch.id)
    ).all()
    views = [service.view(db, batch) for batch in batches]
    # Active batches are always shown ahead of completed history.
    views.sort(
        key=lambda item: (
            item["status"] in {"completed", "completed_with_errors", "cancelled", "expired"},
            item["created_at"],
        )
    )
    return {"items": views[offset : offset + limit], "total": len(views), "limit": limit, "offset": offset}


@router.get("/run-batches/{batch_id}")
def detail(batch_id: UUID, db: Session = Depends(session), p: Principal = Depends(viewer)):
    return service.view(db, need(db, batch_id))


@router.post("/run-batches/{batch_id}/{action}")
def control(
    batch_id: UUID,
    action: Literal["pause", "resume", "cancel"],
    request: Request,
    db: Session = Depends(session),
    p: Principal = Depends(human),
):
    operator(p, "atomic:request")
    batch = need(db, batch_id)
    service.control(db, request.app.state.settings, p, batch, action)
    return service.view(db, batch)
