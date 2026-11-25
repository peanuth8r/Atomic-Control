"""Exercise the delegated MCP submission path without approval or host execution."""

import base64
from uuid import uuid4

import httpx
import pytest
import yaml
from mcp import Client
from mcp.server.auth.provider import AccessToken
from sqlalchemy import func, select

from apps.api.app.auth import Principal, human
from apps.api.app.models import CustomTestSubmission, Run
from apps.mcp.api_client import APIClient
from apps.mcp.server import create_server
from tests.integration.test_custom_tests import document
from tests.integration.test_mcp import RecordingClient, settings


async def test_custom_tool_translation_and_bounded_file_schema():
    recorder = RecordingClient()
    async with Client(create_server(settings(), recorder, "https://mcp.example.invalid/mcp")) as client:
        tool = next(t for t in (await client.list_tools()).tools if t.name == "atomic_add_custom_test")
        assert tool.output_schema is not None
        assert tool.input_schema["properties"]["content"]["maxLength"] == 1_000_000
        assert tool.input_schema["properties"]["files"]["anyOf"][0]["maxItems"] == 127
        file = {"path": "atomics/T1082/src/file.txt", "content_base64": base64.b64encode(b"fixture").decode()}
        result = await client.call_tool(
            "atomic_add_custom_test",
            {
                "content": "fixture YAML",
                "filename": "T1082.yaml",
                "files": [file],
                "idempotency_key": "submission-1",
            },
        )
        assert not result.is_error
        assert recorder.calls[-1] == (
            "POST",
            "/catalog/custom-tests",
            "atomic:request",
            {"filename": "T1082.yaml", "content": "fixture YAML", "files": [file]},
            "submission-1",
        )
        count = len(recorder.calls)
        bad = await client.call_tool(
            "atomic_add_custom_test",
            {"content": "fixture YAML", "filename": "../outside.yaml", "idempotency_key": "submission-1"},
        )
        assert bad.is_error and len(recorder.calls) == count


async def test_custom_tool_requires_scope_before_exchange(monkeypatch):
    monkeypatch.setattr(
        "apps.mcp.api_client.get_access_token",
        lambda: AccessToken(token="not-sent", client_id="reader", scopes=["atomic:read"]),
    )
    client = APIClient(
        "https://api.example.invalid",
        "https://id.example.invalid/token",
        "adapter",
        "secret",
        "atomic-control",
    )
    async with Client(create_server(settings(), client, "https://mcp.example.invalid/mcp")) as mcp:
        result = await mcp.call_tool(
            "atomic_add_custom_test", {"content": "fixture YAML", "idempotency_key": "submission-1"}
        )
        assert result.structured_content["error"]["code"] == "insufficient_scope"


@pytest.mark.parametrize("scopes", [frozenset({"atomic:read"}), frozenset({"atomic:read", "atomic:cleanup"})])
def test_direct_mcp_api_cannot_use_read_or_cleanup_scope_to_submit(env, scopes):
    env["app"].dependency_overrides[human] = lambda: Principal(
        "mcp:restricted", frozenset({"viewer", "operator"}), scopes, True
    )
    response = env["client"].post(
        "/api/v1/catalog/custom-tests",
        headers={"Idempotency-Key": "scope"},
        json={"content": yaml.safe_dump(document())},
    )
    assert response.status_code == 403 and response.json()["error"]["code"] == "insufficient_scope"


async def test_delegated_mcp_submission_cannot_review_replace_or_execute(env, monkeypatch):
    import apps.mcp.api_client as adapter
    from apps.api.app import auth

    claims = {"sub": "mcp:custom-author", "scope": "atomic:read atomic:request", "roles": ["administrator"]}
    monkeypatch.setattr(auth, "verify_oidc", lambda *_: claims)
    monkeypatch.setattr(adapter, "verify_oidc", lambda *_: claims)
    monkeypatch.setattr(
        adapter,
        "get_access_token",
        lambda: AccessToken(
            token="mcp-token", client_id="adapter", subject=claims["sub"], scopes=claims["scope"].split()
        ),
    )
    actual_client = httpx.AsyncClient
    transport = httpx.ASGITransport(app=env["app"])

    async def handle(request):
        if request.url.host == "id.example.invalid":
            assert b"subject_token=mcp-token" in request.content
            return httpx.Response(200, json={"access_token": "delegated-token"})
        return await transport.handle_async_request(request)

    monkeypatch.setattr(
        adapter.httpx,
        "AsyncClient",
        lambda **kwargs: actual_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    api = APIClient(
        "https://api.example.invalid",
        "https://id.example.invalid/token",
        "adapter",
        "secret",
        "atomic-control",
    )
    async with Client(create_server(settings(), api, "https://mcp.example.invalid/mcp")) as client:
        arguments = {"content": yaml.safe_dump(document()), "idempotency_key": "delegated-submission"}
        added = await client.call_tool("atomic_add_custom_test", arguments)
        assert added.structured_content["outcome"] == "submitted"
        receipt = added.structured_content["data"]
        guid = receipt["tests"][0]["guid"]
        assert receipt["submitted_by"] == claims["sub"]
        replay = await client.call_tool("atomic_add_custom_test", arguments)
        assert replay.structured_content["data"]["replayed"]
        test = (await client.call_tool("atomic_get_test_details", {"guid": guid})).structured_content["data"]
        assert not test["approved"]
        review = await api.call(
            "POST",
            f"/tests/{guid}/review",
            "atomic:request",
            {
                "content_sha256": test["content_sha256"],
                "source_revision": test["revision"],
                "allowed_profiles": ["standard-user"],
                "risk_level": "low",
            },
        )
        assert not review["ok"] and review["error"]["code"] == "forbidden"
        run = await client.call_tool(
            "atomic_request_test",
            {
                "guid": guid,
                "actor_id": env["actor"],
                "execution_profile_id": env["profiles"][0]["id"],
                "idempotency_key": "cannot-run-unapproved",
            },
        )
        assert run.structured_content["error"]["code"] == "test_unapproved"
        arguments["idempotency_key"] = str(uuid4())
        overwrite = await client.call_tool("atomic_add_custom_test", arguments)
        assert overwrite.structured_content["error"]["code"] == "custom_guid_conflict"
    with env["app"].state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(CustomTestSubmission)) == 1
        assert db.scalar(select(func.count()).select_from(Run)) == 0
