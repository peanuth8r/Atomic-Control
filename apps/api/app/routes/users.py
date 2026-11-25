"""Human-administrator user creation, role management and deletion."""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import Field, SecretStr, field_validator

from ..auth import Principal, human
from ..schemas import Strict
from ..services import users as service
from ..services.common import audit

router = APIRouter(prefix="/api/v1/admin/users")


class CreateUser(Strict):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    first_name: str = Field(default="", max_length=128)
    last_name: str = Field(default="", max_length=128)
    email: str = Field(default="", max_length=254, pattern=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$")
    access_level: Literal["viewer", "operator", "approver", "administrator"] = "viewer"
    temporary_password: SecretStr = Field(min_length=12, max_length=256)

    @field_validator("username", "first_name", "last_name", "email", mode="before")
    @classmethod
    def trim(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator("username")
    @classmethod
    def human_username(cls, value):
        if value.lower().startswith("service-account-"):
            raise ValueError("Choose a human username")
        return value


def admin(p: Principal = Depends(human)):
    p.require("administrator")
    return p


@router.get("/options")
def options(request: Request, p: Principal = Depends(admin)):
    return service.options(request.app.state.settings)


@router.post("", status_code=201)
def create(
    data: CreateUser, request: Request, idempotency_key: str = Header(), p: Principal = Depends(admin)
):
    def record(action, resource, **details):
        with request.app.state.sessions() as db, db.begin():
            audit(
                db,
                p.subject,
                action,
                resource,
                username=data.username,
                access_level=data.access_level,
                **details,
            )

    # Persist intent before contacting the identity provider, without holding the API database lock.
    if service.configured(request.app.state.settings):
        operation, _ = service.request_binding(request.app.state.settings, p.subject, idempotency_key, data)
        record("user.creation_requested", operation)
    try:
        result = service.create(request.app.state.settings, data, p.subject, idempotency_key)
    except HTTPException as error:
        code = (
            error.detail.get("code", "user_management_unavailable")
            if isinstance(error.detail, dict)
            else "user_management_unavailable"
        )
        record("user.creation_failed", "keycloak", code=code)
        raise
    record(
        "user.creation_replayed" if result["replayed"] else "user.created",
        result["id"],
        roles=result["roles"],
    )
    return result


class ChangeRoles(Strict):
    access_level: Literal["viewer", "operator", "approver", "administrator"]
    expected_version: str = Field(pattern=r"^[a-f0-9]{64}$")


class DeleteUser(Strict):
    expected_version: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm_username: str = Field(min_length=1, max_length=256)


def with_access_state(request, result):
    from ..models import UserAccessState

    with request.app.state.sessions() as db:
        state = db.get(UserAccessState, result["id"])
        return {**result, "access_on_hold": bool(state and state.blocked)}


@router.get("")
def listing(
    request: Request,
    q: str = Query("", max_length=128),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0),
    p: Principal = Depends(admin),
):
    result = service.list_users(request.app.state.settings, q, limit, offset)
    result["items"] = [with_access_state(request, item) for item in result["items"]]
    return result


@router.get("/{user_id}")
def detail(user_id: UUID, request: Request, p: Principal = Depends(admin)):
    return with_access_state(request, service.get_user(request.app.state.settings, user_id))


@router.post("/{user_id}/roles")
def change_roles(user_id: UUID, data: ChangeRoles, request: Request, p: Principal = Depends(admin)):
    return service.change_roles(
        request.app.state.settings, user_id, data, p.subject, request.app.state.sessions
    )


@router.delete("/{user_id}")
def delete_user(user_id: UUID, data: DeleteUser, request: Request, p: Principal = Depends(admin)):
    return service.delete_user(
        request.app.state.settings, user_id, data, p.subject, request.app.state.sessions
    )
