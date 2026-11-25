"""HTTPS host for a real-mode local API/dashboard or its authenticated MCP endpoint."""

import argparse
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

import uvicorn
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import PlainTextResponse
from starlette.staticfiles import StaticFiles

from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.mcp.server import create_server
from apps.mcp.settings import MCPSettings


class Frontend(StaticFiles):
    async def get_response(self, path, scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as error:
            if error.status_code != 404 or path.startswith(("api/", "auth/", ".well-known/")):
                raise
            return await super().get_response("index.html", scope)


class SubnetOnly:
    def __init__(self, app, subnet):
        self.app = app
        self.network = ipaddress.ip_network(subnet)

    async def __call__(self, scope, receive, send):
        if scope["type"] in {"http", "websocket"}:
            try:
                address = ipaddress.ip_address((scope.get("client") or ("", 0))[0])
                allowed = address.is_loopback or address in self.network
            except ValueError:
                allowed = False
            if not allowed:
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    await PlainTextResponse("Local subnet access only", status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("service", choices=["control", "mcp"])
    parser.add_argument("--runtime", required=True, type=Path)
    args = parser.parse_args()
    for key in ["SSL_CERT_FILE", "ATOMIC_MODE", "ATOMIC_DEV_AUTH"]:
        if key not in os.environ:
            raise SystemExit("Load the generated private deployment environment first")
    settings = Settings()
    if settings.mode != "real" or settings.dev_auth:
        raise SystemExit("Local identity verification requires real mode and no development authentication")
    if args.service == "control":
        app = create_app(settings)
        app.mount("/", Frontend(directory=Path.cwd() / "apps/frontend/dist", html=True))
        app.add_middleware(SubnetOnly, subnet=os.environ.get("ATOMIC_ALLOWED_SUBNET", "127.0.0.0/8"))
        app.add_middleware(
            TrustedHostMiddleware, allowed_hosts=[urlsplit(settings.public_url).hostname or ""]
        )
        host = os.environ.get("ATOMIC_BIND_ADDRESS", "127.0.0.1")
        port = 19443
    else:
        from mcp.server.transport_security import TransportSecuritySettings

        resource = os.environ["ATOMIC_MCP_RESOURCE"]
        origin = urlsplit(resource)
        app = create_server(MCPSettings(), resource=resource).streamable_http_app(
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[origin.netloc],
                allowed_origins=[f"{origin.scheme}://{origin.netloc}"],
            ),
        )
        host = "127.0.0.1"
        port = 19444
    uvicorn.run(
        app,
        host=host,
        port=port,
        ssl_certfile=str(args.runtime / "tls" / (args.service + ".pem")),
        ssl_keyfile=str(args.runtime / "tls" / (args.service + "-key.pem")),
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
