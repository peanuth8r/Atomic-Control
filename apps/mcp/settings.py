from pydantic_settings import BaseSettings, SettingsConfigDict


class MCPSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATOMIC_", env_file=".env", extra="ignore")
    oidc_issuer: str = ""
    oidc_jwks_url: str = ""
    oidc_audience: str = "atomic-control"
