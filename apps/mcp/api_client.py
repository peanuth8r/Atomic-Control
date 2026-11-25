import asyncio
import os

import httpx
import jwt
from mcp.server.auth.middleware.auth_context import get_access_token

from apps.api.app.auth import verify_oidc

from .settings import MCPSettings


class APIClient:
    def __init__(self, base_url: str, exchange_url: str, client_id: str, client_secret: str, audience: str):
        if not base_url.startswith("https://") or not exchange_url.startswith("https://"):
            raise ValueError("MCP backend and token exchange require HTTPS")
        self.base_url, self.exchange_url = base_url, exchange_url
        self.client_id, self.client_secret, self.audience = client_id, client_secret, audience

    async def call(
        self, method: str, path: str, scope: str, body: dict | None = None, key: str | None = None
    ) -> dict:
        caller = get_access_token()
        if not caller or scope not in caller.scopes:
            return {
                "ok": False,
                "outcome": "unauthorized",
                "error": {"code": "insufficient_scope", "message": f"Required scope: {scope}"},
            }
        # RFC 8693 delegated access: never use an administrator service token for callers.
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as http:
            exchange = await http.post(
                self.exchange_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token": caller.token,
                    "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "audience": self.audience,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": " ".join(
                        s for s in caller.scopes if s in {"atomic:read", "atomic:request", "atomic:cleanup"}
                    ),
                },
            )
            if exchange.status_code != 200:
                return {
                    "ok": False,
                    "outcome": "unauthorized",
                    "error": {"code": "delegation_failed", "message": "OIDC token exchange refused"},
                }
            delegated = exchange.json()["access_token"]
            try:
                claims = await asyncio.to_thread(verify_oidc, delegated, MCPSettings(), self.audience)
                delegated_scopes = set(claims.get("scope", "").split())
                if (
                    claims["sub"] != caller.subject
                    or scope not in delegated_scopes
                    or not delegated_scopes <= set(caller.scopes)
                ):
                    raise ValueError("Delegated token changed caller or expanded scopes")
            except (jwt.PyJWTError, ValueError):
                return {
                    "ok": False,
                    "outcome": "unauthorized",
                    "error": {
                        "code": "invalid_delegation",
                        "message": "Delegated identity or scopes do not match caller",
                    },
                }
            headers = {"Authorization": "Bearer " + delegated}
            if key:
                headers["Idempotency-Key"] = key
            response = await http.request(
                method, self.base_url.rstrip("/") + "/api/v1" + path, json=body, headers=headers
            )
            data = response.json()
            if response.is_error:
                return {"ok": False, "outcome": data.get("error", {}).get("code", "api_error"), **data}
            return {
                "ok": True,
                "outcome": data.get("status", "retrieved") if isinstance(data, dict) else "retrieved",
                "data": data,
            }


def configured_client():
    return APIClient(
        os.environ["ATOMIC_API_URL"],
        os.environ["ATOMIC_TOKEN_EXCHANGE_URL"],
        os.environ["ATOMIC_MCP_CLIENT_ID"],
        os.environ["ATOMIC_MCP_CLIENT_SECRET"],
        os.environ.get("ATOMIC_OIDC_AUDIENCE", "atomic-control"),
    )
