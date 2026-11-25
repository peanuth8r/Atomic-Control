from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATOMIC_", env_file=".env", extra="ignore")
    github_token: SecretStr = SecretStr("")
    user_management_provider: Literal["disabled", "keycloak"] = "disabled"
    keycloak_management_client_id: str = ""
    keycloak_management_client_secret: SecretStr = SecretStr("")
    database_url: str = "sqlite:///./atomic-control.db"
    mode: Literal["real"] = "real"
    dev_auth: Literal[False] = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    browser_session_seconds: int = Field(default=86400, ge=300, le=86400)
    browser_session_key_file: str = ""
    public_url: str = "https://localhost"
    oidc_audience: str = "atomic-control"
    oidc_jwks_url: str = ""
    mcp_client_ids: str = ""
    policy_file: str = ""
    approval_mode: Literal["catalog", "per_run"] = "catalog"
    signing_key_file: str = ""
    agent_public_ca_file: str = ""
    artifact_worker_enabled: bool = True
    artifact_build_seconds: int = Field(default=300, ge=30, le=1800)
    artifact_preparation_seconds: int = Field(default=300, ge=30, le=1800)
    heartbeat_threshold: int = 90
    lease_seconds: int = 60
    approval_seconds: int = 1800
    queue_lifetime_seconds: int = Field(default=86400, ge=300, le=604800)
    credential_seconds: int = 86400
    log_limit: int = 65536

    @field_validator("dev_auth", mode="before")
    @classmethod
    def reject_development_auth(cls, value):
        if value is False or (isinstance(value, str) and value.lower() in {"false", "0"}):
            return False
        raise ValueError("Development authentication is not supported")

    @model_validator(mode="after")
    def secure_defaults(self):
        if not self.signing_key_file or not self.oidc_issuer:
            raise ValueError("Execution requires OIDC and a signing key")
        if self.oidc_issuer and (
            not self.oidc_issuer.startswith("https://") or not self.oidc_jwks_url.startswith("https://")
        ):
            raise ValueError("OIDC issuer and JWKS endpoint must use HTTPS")
        return self
