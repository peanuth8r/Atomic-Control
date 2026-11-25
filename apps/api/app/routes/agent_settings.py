import time

from fastapi import APIRouter, Depends
from pydantic import Field
from sqlalchemy.orm import Session

from ..auth import Principal
from ..db import session
from ..models import AgentSettings
from ..schemas import Strict
from ..services.agent_settings import enrollment_minutes
from ..services.common import audit
from .catalog import administrator

router = APIRouter(prefix="/api/v1/admin/agent-settings", tags=["Agent settings"])


class EnrollmentSettings(Strict):
    enrollment_token_minutes: int = Field(ge=5, le=1440, strict=True)


@router.get("")
def read(db: Session = Depends(session), p: Principal = Depends(administrator)):
    return {"enrollment_token_minutes": enrollment_minutes(db)}


@router.put("")
def update(data: EnrollmentSettings, db: Session = Depends(session), p: Principal = Depends(administrator)):
    previous = enrollment_minutes(db)
    settings = db.get(AgentSettings, 1, with_for_update=True)
    if settings is None:
        settings = AgentSettings(id=1)
        db.add(settings)
    settings.enrollment_token_minutes = data.enrollment_token_minutes
    settings.updated_at = time.time()
    settings.updated_by = p.subject
    audit(
        db,
        p.subject,
        "agent.settings-updated",
        "agent-enrollment",
        previous_minutes=previous,
        enrollment_token_minutes=data.enrollment_token_minutes,
    )
    return data.model_dump()
