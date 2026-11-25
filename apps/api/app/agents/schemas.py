import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from ..schemas import Strict


class RegisterActor(Strict):
    hostname: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")
    os: Literal["windows", "linux"] = "windows"


class AgentPackageRequest(Strict):
    delivery_mode: Literal["checkout", "on_demand"] = "on_demand"
    api_url: str = Field(min_length=10, max_length=256)
    include_enrollment: bool = False
    catalog_revision: str = Field(default="", max_length=40, pattern=r"^(?:[a-f0-9]{40})?$")

    @model_validator(mode="before")
    @classmethod
    def legacy_catalog_selection(cls, value):
        if isinstance(value, dict) and value.get("catalog_revision") and "delivery_mode" not in value:
            return {**value, "delivery_mode": "checkout"}
        return value

    @field_validator("api_url")
    @classmethod
    def https_origin(cls, value):
        parts = urlsplit(value)
        try:
            port = parts.port
        except ValueError:
            raise ValueError("Invalid HTTPS port") from None
        if (
            any(ord(c) < 33 for c in value)
            or not re.fullmatch(r"[A-Za-z0-9.:-]+", parts.hostname or "")
            or parts.scheme != "https"
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
            or (port is not None and port < 1)
        ):
            raise ValueError(
                "Enter the HTTPS origin reachable from the agent host, without credentials, path, query or fragment"
            )
        return value.rstrip("/")
