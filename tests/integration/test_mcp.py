import httpx
import pytest
from mcp import Client
from mcp.server.auth.provider import AccessToken

from apps.api.app.config import Settings
from apps.mcp.api_client import APIClient
from apps.mcp.server import create_server


class RecordingClient:
    def __init__(self):
        self.calls = []

    async def call(self, *args):
        self.calls.append(args)
        return {
            "ok": True,
            "outcome": "pending_approval",
            "data": {"status": "pending_approval", "approval_required": True},
        }


def settings():
    return Settings(
        oidc_issuer="https://id.example.invalid",
        oidc_jwks_url="https://id.example.invalid/jwks",
        dev_auth=False,
    )


async def test_fourteen_tools_no_approval_and_validated_translation():
    recorder = RecordingClient()
    server = create_server(settings(), recorder, "https://mcp.example.invalid/mcp")
    async with Client(server) as client:
        tools = await client.list_tools()
        assert len(tools.tools) == 14
        assert all(tool.output_schema is not None for tool in tools.tools)
        assert all("approv" not in t.name for t in tools.tools)
        guid = "11111111-1111-4111-8111-111111111111"
        result = await client.call_tool(
            "atomic_request_test",
            {
                "guid": guid,
                "actor_id": guid,
                "execution_profile_id": guid,
                "reason": "Validate isolated lab telemetry",
                "idempotency_key": "mcp-request-1",
            },
        )
        assert not result.is_error
        assert recorder.calls[-1] == (
            "POST",
            "/runs",
            "atomic:request",
            {
                "atomic_guid": guid,
                "actor_id": guid,
                "execution_profile_id": guid,
                "reason": "Validate isolated lab telemetry",
            },
            "mcp-request-1",
        )
        assert "pending_approval" in str(result)
        bad = await client.call_tool("atomic_get_execution", {"run_id": "not-a-guid"})
        assert bad.is_error


async def test_mcp_http_auth_required():
    server = create_server(settings(), RecordingClient(), "https://mcp.example.invalid/mcp")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.streamable_http_app()),
        base_url="https://mcp.example.invalid",
    ) as client:
        response = await client.post("/mcp", json={"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        assert response.status_code == 401
        metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.json()["resource"] == "https://mcp.example.invalid/mcp"


async def test_adapter_refuses_missing_scope(monkeypatch):
    monkeypatch.setattr(
        "apps.mcp.api_client.get_access_token",
        lambda: AccessToken(token="never-sent", client_id="operator", scopes=["atomic:read"]),
    )
    client = APIClient(
        "https://api.example.invalid",
        "https://id.example.invalid/token",
        "adapter",
        "secret",
        "atomic-control",
    )
    response = await client.call("POST", "/runs", "atomic:request", {})
    assert response["outcome"] == "unauthorized"


@pytest.mark.parametrize(
    "subject,scopes,allowed",
    [
        ("original", "atomic:read atomic:request", True),
        ("administrator", "atomic:read atomic:request", False),
        ("original", "atomic:read atomic:request atomic:cleanup", False),
    ],
)
async def test_token_exchange_cannot_change_caller_or_expand_scopes(monkeypatch, subject, scopes, allowed):
    import apps.mcp.api_client as module

    caller = AccessToken(
        token="mcp-resource-token",
        client_id="client",
        subject="original",
        scopes=["atomic:read", "atomic:request"],
    )
    monkeypatch.setattr(module, "get_access_token", lambda: caller)
    monkeypatch.setattr(module, "verify_oidc", lambda *_: {"sub": subject, "scope": scopes})
    actual_client = httpx.AsyncClient
    backend_calls = []

    def handler(request):
        if str(request.url) == "https://id.example.invalid/token":
            assert b"subject_token=mcp-resource-token" in request.content
            return httpx.Response(200, json={"access_token": "delegated-api-token"})
        backend_calls.append(request)
        assert request.headers["authorization"] == "Bearer delegated-api-token"
        assert request.headers["idempotency-key"] == "stable"
        return httpx.Response(201, json={"status": "pending_approval"})

    monkeypatch.setattr(
        module.httpx,
        "AsyncClient",
        lambda **kwargs: actual_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    client = APIClient(
        "https://api.example.invalid",
        "https://id.example.invalid/token",
        "adapter",
        "secret",
        "atomic-control",
    )
    response = await client.call(
        "POST", "/runs", "atomic:request", {"reason": "Authorized lab validation"}, "stable"
    )
    assert response["ok"] == allowed
    assert len(backend_calls) == int(allowed)


async def test_mcp_request_human_approval_agent_result_through_rest(env, monkeypatch):
    import apps.mcp.api_client as adapter
    from apps.api.app import auth
    from apps.api.app.auth import Principal, human
    from tests.support.fixtures import fixture_result

    env["app"].state.settings.dev_auth = False
    env["app"].state.settings.oidc_issuer = "https://id.example.invalid"
    claims = {"sub": "mcp:operator", "scope": "atomic:read atomic:request", "roles": ["administrator"]}
    monkeypatch.setattr(auth, "verify_oidc", lambda *_: claims)
    monkeypatch.setattr(adapter, "verify_oidc", lambda *_: claims)
    monkeypatch.setattr(
        adapter,
        "get_access_token",
        lambda: AccessToken(
            token="mcp-token",
            client_id="adapter",
            subject="mcp:operator",
            scopes=["atomic:read", "atomic:request"],
        ),
    )
    actual_client = httpx.AsyncClient
    transport = httpx.ASGITransport(app=env["app"])

    async def handle(request):
        if request.url.host == "id.example.invalid":
            return httpx.Response(200, json={"access_token": "delegated-token"})
        return await transport.handle_async_request(request)

    monkeypatch.setattr(
        adapter.httpx,
        "AsyncClient",
        lambda **kwargs: actual_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    api_client = APIClient(
        "https://api.example.invalid",
        "https://id.example.invalid/token",
        "adapter",
        "secret",
        "atomic-control",
    )
    server = create_server(settings(), api_client, "https://mcp.example.invalid/mcp")
    guid = "11111111-1111-4111-8111-111111111111"
    profile = env["profiles"][0]["id"]
    async with Client(server) as client:
        pending = await client.call_tool(
            "atomic_request_test",
            {
                "guid": guid,
                "actor_id": env["actor"],
                "execution_profile_id": profile,
                "reason": "MCP initiated authorized simulated validation",
                "idempotency_key": "mcp-full-workflow",
            },
        )
        assert not pending.is_error
        content = pending.structured_content
        assert content["outcome"] == "pending_approval"
        run_id = content["data"]["run_id"]
        assert (
            env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={}).json()["job"]
            is None
        )
        env["app"].dependency_overrides[human] = lambda: Principal(
            "human:approver", frozenset({"approver", "privileged_approver", "viewer"}), frozenset()
        )
        approved = env["client"].post(
            f"/api/v1/runs/{run_id}/approve", json={"reason": "Human review of MCP requested lab validation"}
        )
        assert approved.status_code == 200, approved.text
        env["app"].dependency_overrides.clear()
        job = env["client"].post("/api/v1/agents/jobs/claim", headers=env["agent"], json={}).json()["job"]
        env["client"].post(
            f"/api/v1/agents/jobs/{run_id}/result", headers=env["agent"], json=fixture_result(job)
        ).raise_for_status()
        finished = await client.call_tool("atomic_get_execution", {"run_id": run_id})
        assert finished.structured_content["data"]["status"] == "succeeded"
        assert finished.structured_content["data"]["requested_by"] == "mcp:operator"
        assert finished.structured_content["data"]["approved_by"] == "human:approver"


async def test_queue_tools_translate_order_hash_idempotency_and_controls():
    recorder = RecordingClient()
    server = create_server(settings(), recorder, "https://mcp.example.invalid/mcp")
    actor, profile = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
    guids = [profile, actor]
    async with Client(server) as client:
        preview = await client.call_tool(
            "atomic_preview_queue",
            {"actor_id": actor, "execution_profile_id": profile, "atomic_guids": guids},
        )
        assert not preview.is_error
        assert recorder.calls[-1] == (
            "POST",
            f"/actors/{actor}/queue/preview",
            "atomic:read",
            {"execution_profile_id": profile, "atomic_guids": guids, "timeout_seconds": 120},
        )
        result = await client.call_tool(
            "atomic_queue_tests",
            {
                "actor_id": actor,
                "execution_profile_id": profile,
                "atomic_guids": guids,
                "preview_hash": "a" * 64,
                "reason": "Authorized batch validation",
                "idempotency_key": "stable-batch",
            },
        )
        assert not result.is_error
        assert recorder.calls[-1][2] == "atomic:request"
        assert recorder.calls[-1][3]["atomic_guids"] == guids
        assert recorder.calls[-1][3]["preview_hash"] == "a" * 64
        assert recorder.calls[-1][3]["failure_policy"] == "continue"
        assert recorder.calls[-1][4] == "stable-batch"
        await client.call_tool("atomic_get_queue", {"actor_id": actor, "offset": 50})
        assert recorder.calls[-1] == ("GET", f"/actors/{actor}/queue?limit=50&offset=50", "atomic:read")
        await client.call_tool("atomic_get_batch", {"batch_id": actor})
        assert recorder.calls[-1] == ("GET", f"/run-batches/{actor}", "atomic:read")
        await client.call_tool("atomic_control_batch", {"batch_id": actor, "action": "cancel"})
        assert recorder.calls[-1] == ("POST", f"/run-batches/{actor}/cancel", "atomic:request", {})
        invalid = await client.call_tool("atomic_control_batch", {"batch_id": actor, "action": "approve"})
        assert invalid.is_error


async def test_testing_reasons_are_optional_but_cleanup_reason_is_required():
    recorder = RecordingClient()
    server = create_server(settings(), recorder, "https://mcp.example.invalid/mcp")
    guid = "11111111-1111-4111-8111-111111111111"
    async with Client(server) as client:
        schemas = {tool.name: tool.input_schema for tool in (await client.list_tools()).tools}
        for name in ["atomic_request_test", "atomic_check_prerequisites", "atomic_queue_tests"]:
            assert "reason" not in schemas[name].get("required", [])
        assert "reason" in schemas["atomic_cleanup_test"]["required"]
        for name in ["atomic_request_test", "atomic_check_prerequisites"]:
            result = await client.call_tool(
                name, {"guid": guid, "actor_id": guid, "execution_profile_id": guid, "idempotency_key": name}
            )
            assert not result.is_error
            assert recorder.calls[-1][3]["reason"] == ""
        result = await client.call_tool(
            "atomic_queue_tests",
            {
                "actor_id": guid,
                "execution_profile_id": guid,
                "atomic_guids": [guid],
                "preview_hash": "a" * 64,
                "idempotency_key": "optional-batch-reason",
            },
        )
        assert not result.is_error
        assert recorder.calls[-1][3]["reason"] == ""
