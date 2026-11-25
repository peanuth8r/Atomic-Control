"""Persisted settings for initial agent enrollment, separate from machine credentials."""

from sqlalchemy.orm import Session

from ..models import AgentSettings

DEFAULT_ENROLLMENT_MINUTES = 60


def enrollment_minutes(db: Session) -> int:
    settings = db.get(AgentSettings, 1)
    return settings.enrollment_token_minutes if settings else DEFAULT_ENROLLMENT_MINUTES


def enrollment_seconds(db: Session) -> int:
    return enrollment_minutes(db) * 60
