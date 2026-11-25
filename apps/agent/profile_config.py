"""Versioned profile-only configuration protocol shared by the API and agent."""

import hashlib
import json
from typing import Literal
from uuid import UUID

import jwt
from pydantic import BaseModel, ConfigDict, Field, model_validator

ISSUER = "atomic-control-profile-sync"
FIELDS = (
    "id",
    "profile_key",
    "display_name",
    "account",
    "expected_sid",
    "privilege",
    "logon_type",
    "enabled",
)


class LinuxProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    profile_key: Literal["standard-user", "local-admin"]
    display_name: str = Field(min_length=1, max_length=128)
    account: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    expected_sid: str = Field(pattern=r"^uid:(?:0|[1-9]\d{0,9})$")
    privilege: Literal["standard", "elevated"]
    logon_type: Literal["systemd"]
    enabled: bool

    @model_validator(mode="after")
    def identity(self):
        UUID(self.id)
        root = self.privilege == "elevated"
        if root != (self.expected_sid == "uid:0") or root != (self.profile_key == "local-admin"):
            raise ValueError("Profile privilege and UID disagree")
        return self


class WindowsProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str
    profile_key: Literal["standard-user", "local-admin"]
    display_name: str = Field(min_length=1, max_length=128)
    account: str = Field(min_length=1, max_length=128)
    expected_sid: str = Field(pattern=r"^S-1-5-(?:\d+-)*\d+$")
    privilege: Literal["standard", "elevated"]
    logon_type: Literal["batch"]
    enabled: bool

    @model_validator(mode="after")
    def identity(self):
        UUID(self.id)
        if (self.profile_key == "local-admin") != (self.privilege == "elevated"):
            raise ValueError("Profile type and privilege disagree")
        return self


class ProfileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    protocol: Literal[1]
    actor_id: str
    hostname: str = Field(min_length=1, max_length=128)
    os: Literal["linux", "windows"]
    profiles: list[LinuxProfile | WindowsProfile] = Field(max_length=2)

    @model_validator(mode="after")
    def unique(self):
        UUID(self.actor_id)
        if any(isinstance(p, LinuxProfile) != (self.os == "linux") for p in self.profiles):
            raise ValueError("Profile belongs to another platform")
        for field in ("id", "profile_key"):
            if len({getattr(p, field) for p in self.profiles}) != len(self.profiles):
                raise ValueError("Duplicate profile identity")
        return self


def payload(config: dict) -> dict:
    return ProfileConfig.model_validate(
        {
            "protocol": 1,
            "actor_id": config["actor_id"],
            "hostname": config["hostname"],
            "os": config["os"],
            "profiles": sorted(
                [{k: p[k] for k in FIELDS} for p in config["profiles"]], key=lambda p: p["id"]
            ),
        }
    ).model_dump()


def fingerprint(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def applied_hash(config: dict) -> str:
    try:
        return fingerprint(payload(config))
    except (KeyError, ValueError, TypeError):
        # Older manually maintained configs may omit display/logon metadata.
        # Advertise drift so the first signed snapshot can repair those fields.
        return "0" * 64


def verify_manifest(token: str, config: dict, key: str) -> dict:
    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=config["actor_id"],
        options={
            "require": ["exp", "iat", "iss", "aud", "jti", "generation", "payload", "payload_hash", "type"]
        },
    )
    UUID(claims["jti"])
    if (
        claims["type"] != "profile-sync-v1"
        or type(claims["generation"]) is not int
        or claims["generation"] < 1
    ):
        raise ValueError("Invalid profile configuration generation/type")
    value = ProfileConfig.model_validate(claims["payload"]).model_dump()
    if any(value[k] != config[k] for k in ["actor_id", "hostname", "os"]):
        raise ValueError("Configuration belongs to another actor")
    if fingerprint(value) != claims["payload_hash"]:
        raise ValueError("Profile configuration hash mismatch")
    previous = config.get("profile_sync_generation", 0)
    if claims["generation"] < previous or (
        claims["generation"] == previous and config.get("profile_sync_hash") != claims["payload_hash"]
    ):
        raise ValueError("Replayed/conflicting profile configuration")
    return claims
