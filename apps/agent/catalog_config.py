"""Signed, fixed-source catalog installation protocol. Contains no executable commands."""

from typing import Literal
from uuid import UUID

import jwt
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .profile_config import fingerprint

ISSUER = "atomic-control-catalog-sync"
SOURCE = "redcanaryco/atomic-red-team"
REMOTE = "https://github.com/redcanaryco/atomic-red-team.git"


class DefinitionHash(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    guid: str
    technique: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def valid_id(self):
        UUID(self.guid)
        return self


class CatalogConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    protocol: Literal[1]
    actor_id: str
    hostname: str = Field(min_length=1, max_length=128)
    os: Literal["linux"]
    source: Literal["redcanaryco/atomic-red-team"]
    revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    tests: list[DefinitionHash] = Field(min_length=1, max_length=10000)

    @model_validator(mode="after")
    def unique(self):
        UUID(self.actor_id)
        if len({t.guid for t in self.tests}) != len(self.tests):
            raise ValueError("Duplicate catalog definition")
        return self


def verify_manifest(token: str, config: dict, key: str) -> dict:
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=config["actor_id"],
        options={
            "require": ["exp", "iat", "iss", "aud", "jti", "type", "generation", "payload", "payload_hash"]
        },
    )
    UUID(claims["jti"])
    if (
        claims["type"] != "catalog-install-v1"
        or type(claims["generation"]) is not int
        or claims["generation"] < 1
    ):
        raise ValueError("Invalid catalog deployment generation/type")
    value = CatalogConfig.model_validate(claims["payload"]).model_dump()
    if (
        any(value[k] != config[k] for k in ("actor_id", "hostname", "os"))
        or fingerprint(value) != claims["payload_hash"]
    ):
        raise ValueError("Catalog actor or payload binding differs")
    previous = config.get("catalog_sync_generation", 0)
    if claims["generation"] < previous or (
        claims["generation"] == previous and config.get("catalog_sync_hash") != claims["payload_hash"]
    ):
        raise ValueError("Replayed/conflicting catalog deployment")
    return claims
