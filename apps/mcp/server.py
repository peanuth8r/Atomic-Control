import os
from typing import Annotated, Any, Literal
from uuid import UUID

from mcp.server import MCPServer
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyHttpUrl, Field

from apps.api.app.schemas import ArtifactFile

from .api_client import configured_client
from .auth import OIDCTokenVerifier
from .settings import MCPSettings

Reason = Annotated[str, Field(min_length=8, max_length=2000)]
TestingReason = Annotated[str | None, Field(max_length=2000)]
Key = Annotated[str, Field(min_length=1, max_length=128)]


def create_server(settings=None, client=None, resource=None):
    settings = settings or MCPSettings()
    resource = resource or os.environ["ATOMIC_MCP_RESOURCE"]
    if not settings.oidc_issuer.startswith("https://") or not settings.oidc_jwks_url.startswith("https://"):
        raise ValueError("Authenticated MCP requires OIDC")
    client = client or configured_client()
    server = MCPServer(
        "Atomic Control",
        version="0.1.0",
        token_verifier=OIDCTokenVerifier(settings, resource),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(settings.oidc_issuer),
            resource_server_url=AnyHttpUrl(resource),
            required_scopes=["atomic:read"],
            validate_token_resource=True,
        ),
    )

    register_atomic_tools(server, client)
    return server


def register_atomic_tools(server, client):
    @server.tool(structured_output=True)
    async def atomic_add_custom_test(
        content: Annotated[str, Field(min_length=1, max_length=1_000_000)],
        idempotency_key: Key,
        filename: Annotated[
            str, Field(max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*\.ya?ml$")
        ] = "custom.yaml",
        files: Annotated[list[ArtifactFile], Field(max_length=127)] | None = None,
    ) -> dict[str, Any]:
        """Submit Atomic technique YAML and optional base64 supporting files as NEW, UNAPPROVED catalog tests. Needs atomic:request. Never overwrites GUIDs, approves tests or starts execution. Custom tests need no GitHub commit; an administrator reviews them in Test Catalog. Reuse the same idempotency key and exact inputs after transport failure."""
        return await client.call(
            "POST",
            "/catalog/custom-tests",
            "atomic:request",
            {"filename": filename, "content": content, "files": [item.model_dump() for item in files or []]},
            idempotency_key,
        )

    @server.tool(structured_output=True)
    async def atomic_list_tests(
        query: str = "",
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        """Discover reviewed tests. Catalog import never authorizes execution."""
        from urllib.parse import urlencode

        return await client.call(
            "GET",
            "/tests?" + urlencode({"approved_only": "true", "q": query, "limit": limit, "offset": offset}),
            "atomic:read",
        )

    @server.tool(structured_output=True)
    async def atomic_get_test_details(guid: UUID) -> dict[str, Any]:
        """Retrieve the exact reviewed definition and catalog revision."""
        return await client.call("GET", f"/tests/{guid}", "atomic:read")

    @server.tool(structured_output=True)
    async def atomic_list_actors(
        limit: Annotated[int, Field(ge=1, le=200)] = 50, offset: Annotated[int, Field(ge=0)] = 0
    ) -> dict[str, Any]:
        """List registered hosts with heartbeat and execution availability."""
        return await client.call("GET", f"/actors?limit={limit}&offset={offset}", "atomic:read")

    @server.tool(structured_output=True)
    async def atomic_list_execution_profiles(actor_id: UUID) -> dict[str, Any]:
        """List preprovisioned execution identities on one actor."""
        return await client.call("GET", f"/actors/{actor_id}/profiles", "atomic:read")

    @server.tool(structured_output=True)
    async def atomic_check_prerequisites(
        guid: UUID,
        actor_id: UUID,
        execution_profile_id: UUID,
        idempotency_key: Key,
        reason: TestingReason = "",
    ) -> dict[str, Any]:
        """Request a human-approved prerequisite check, which can execute dependency commands."""
        return await client.call(
            "POST",
            "/runs",
            "atomic:request",
            {
                "atomic_guid": str(guid),
                "actor_id": str(actor_id),
                "execution_profile_id": str(execution_profile_id),
                "reason": reason,
                "action": "check",
            },
            idempotency_key,
        )

    @server.tool(structured_output=True)
    async def atomic_request_test(
        guid: UUID,
        actor_id: UUID,
        execution_profile_id: UUID,
        idempotency_key: Key,
        reason: TestingReason = "",
    ) -> dict[str, Any]:
        """Request an approved test. Catalog mode queues directly; per-run mode awaits human approval. Acceptance is not execution success."""
        return await client.call(
            "POST",
            "/runs",
            "atomic:request",
            {
                "atomic_guid": str(guid),
                "actor_id": str(actor_id),
                "execution_profile_id": str(execution_profile_id),
                "reason": reason,
            },
            idempotency_key,
        )

    @server.tool(structured_output=True)
    async def atomic_get_execution(run_id: UUID) -> dict[str, Any]:
        """Retrieve actual execution status, identity evidence and result."""
        return await client.call("GET", f"/runs/{run_id}", "atomic:read")

    @server.tool(structured_output=True)
    async def atomic_cleanup_test(run_id: UUID, reason: Reason, idempotency_key: Key) -> dict[str, Any]:
        """Request cleanup of a completed execution under the deployment's catalog/per-run approval mode."""
        return await client.call(
            "POST", f"/runs/{run_id}/cleanup", "atomic:cleanup", {"reason": reason}, idempotency_key
        )

    @server.tool(structured_output=True)
    async def atomic_preview_queue(
        actor_id: UUID,
        execution_profile_id: UUID,
        atomic_guids: Annotated[list[UUID], Field(min_length=1, max_length=500)],
        timeout_seconds: Annotated[int, Field(ge=10, le=600)] = 120,
    ) -> dict[str, Any]:
        """Preview an ordered test selection; return eligible/excluded tests and its bound preview hash. Creates no executions."""
        return await client.call(
            "POST",
            f"/actors/{actor_id}/queue/preview",
            "atomic:read",
            {
                "execution_profile_id": str(execution_profile_id),
                "atomic_guids": [str(guid) for guid in atomic_guids],
                "timeout_seconds": timeout_seconds,
            },
        )

    @server.tool(structured_output=True)
    async def atomic_queue_tests(
        actor_id: UUID,
        execution_profile_id: UUID,
        atomic_guids: Annotated[list[UUID], Field(min_length=1, max_length=500)],
        preview_hash: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")],
        idempotency_key: Key,
        reason: TestingReason = "",
        name: Annotated[str, Field(min_length=1, max_length=128)] = "Selected catalog tests",
        timeout_seconds: Annotated[int, Field(ge=10, le=600)] = 120,
        failure_policy: Literal["pause", "continue"] = "continue",
    ) -> dict[str, Any]:
        """Submit a previewed batch on one actor in order. Catalog mode queues; per-run mode needs human approvals. Reuse the same key and arguments after transport failures."""
        return await client.call(
            "POST",
            f"/actors/{actor_id}/queue",
            "atomic:request",
            {
                "execution_profile_id": str(execution_profile_id),
                "atomic_guids": [str(guid) for guid in atomic_guids],
                "preview_hash": preview_hash,
                "reason": reason,
                "name": name,
                "timeout_seconds": timeout_seconds,
                "failure_policy": failure_policy,
            },
            idempotency_key,
        )

    @server.tool(structured_output=True)
    async def atomic_get_queue(
        actor_id: UUID,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> dict[str, Any]:
        """List an actor's durable batches, with active work first and per-test execution IDs."""
        return await client.call(
            "GET", f"/actors/{actor_id}/queue?limit={limit}&offset={offset}", "atomic:read"
        )

    @server.tool(structured_output=True)
    async def atomic_get_batch(batch_id: UUID) -> dict[str, Any]:
        """Inspect ordered execution states, progress, expiry and pause reason for one batch."""
        return await client.call("GET", f"/run-batches/{batch_id}", "atomic:read")

    @server.tool(structured_output=True)
    async def atomic_control_batch(
        batch_id: UUID, action: Literal["pause", "resume", "cancel"]
    ) -> dict[str, Any]:
        """Pause, resume or cancel remaining tests. Active execution finishes; uncertain outcomes need dashboard reconciliation before resuming."""
        return await client.call("POST", f"/run-batches/{batch_id}/{action}", "atomic:request", {})


if __name__ == "__main__":
    from urllib.parse import urlparse

    from mcp.server.transport_security import TransportSecuritySettings

    resource = os.environ["ATOMIC_MCP_RESOURCE"]
    public = urlparse(resource)
    create_server(resource=resource).run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8001,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[public.netloc],
            allowed_origins=[public.scheme + "://" + public.netloc],
        ),
    )
