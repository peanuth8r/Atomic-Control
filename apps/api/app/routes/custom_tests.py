from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from ..auth import Principal, human
from ..catalog.custom_schemas import CustomTestCreate, CustomTestReceipt
from ..db import session
from ..services.custom_tests import submit

router = APIRouter(prefix="/api/v1/catalog/custom-tests", tags=["Custom tests"])


@router.post("", response_model=CustomTestReceipt, status_code=201)
def add_custom_tests(
    data: CustomTestCreate,
    idempotency_key: str = Header(),
    db: Session = Depends(session),
    principal: Principal = Depends(human),
):
    return submit(db, principal, data, idempotency_key)
