from typing import NoReturn

from fastapi import HTTPException


def fail(code: str, message: str, status: int = 409) -> NoReturn:
    raise HTTPException(status, {"code": code, "message": message})
