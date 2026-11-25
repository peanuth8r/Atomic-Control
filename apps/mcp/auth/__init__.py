import asyncio

import jwt
from mcp.server.auth.provider import AccessToken

from apps.api.app.auth import verify_oidc


class OIDCTokenVerifier:
    def __init__(self, settings, resource: str):
        self.settings, self.resource = settings, resource

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = await asyncio.to_thread(verify_oidc, token, self.settings, self.resource)
            return AccessToken(
                token=token,
                client_id=claims.get("azp", claims["sub"]),
                subject=claims["sub"],
                scopes=claims.get("scope", "").split(),
                expires_at=claims["exp"],
                resource=self.resource,
                claims=claims,
            )
        except jwt.PyJWTError:
            return None
