"""Optional execution context must not change execution authorization."""

from uuid import uuid4

import pytest

from tests.integration.test_run_batches import queue_env as queue_env

GUID = "11111111-1111-4111-8111-111111111111"
OP = {"X-Test-User": "operator"}


def body(env):
    return {"atomic_guid": GUID, "actor_id": env["actor"], "execution_profile_id": env["profiles"][0]["id"]}


@pytest.mark.parametrize("mode", ["catalog", "per_run"])
@pytest.mark.parametrize("action", ["execute", "check"])
def test_omitted_reason_preserves_authorization_and_idempotency(env, mode, action):
    env["settings"].approval_mode = mode
    payload = {**body(env), "action": action}
    headers = {**OP, "Idempotency-Key": str(uuid4())}
    response = env["client"].post("/api/v1/runs", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["reason"] == ""
    assert run["status"] == ("queued" if mode == "catalog" else "pending_approval")
    replay = env["client"].post("/api/v1/runs", headers=headers, json={**payload, "reason": ""})
    assert replay.json()["run_id"] == run["run_id"]
    assert env["client"].get(f"/api/v1/runs/{run['run_id']}").json()["reason"] == ""


@pytest.mark.parametrize(
    ("reason", "stored"), [(None, ""), ("", ""), ("  ", ""), ("x", "x"), ("  investigate  ", "investigate")]
)
def test_optional_reason_values_are_retained_in_history(env, reason, stored):
    response = env["client"].post(
        "/api/v1/runs", headers={**OP, "Idempotency-Key": str(uuid4())}, json={**body(env), "reason": reason}
    )
    assert response.status_code == 201, response.text
    assert env["client"].get(f"/api/v1/runs/{response.json()['run_id']}").json()["reason"] == stored


def test_reason_limit_and_administrative_justification_remain(env):
    response = env["client"].post(
        "/api/v1/runs",
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={**body(env), "reason": "x" * 2001},
    )
    assert response.status_code == 422
    run = (
        env["client"]
        .post("/api/v1/runs", headers={**OP, "Idempotency-Key": str(uuid4())}, json=body(env))
        .json()
    )
    assert (
        env["client"]
        .post(f"/api/v1/runs/{run['run_id']}/approve", headers={"X-Test-User": "approver"}, json={})
        .status_code
        == 422
    )


@pytest.mark.parametrize("mode", ["catalog", "per_run"])
def test_queue_and_children_accept_omitted_reason(queue_env, mode):
    env = queue_env
    env["settings"].approval_mode = mode
    path = f"/api/v1/actors/{env['actor']}/queue"
    payload = {"execution_profile_id": env["profile"], "atomic_guids": env["guids"]}
    preview = env["client"].post(path + "/preview", headers=OP, json=payload)
    assert preview.status_code == 200
    response = env["client"].post(
        path,
        headers={**OP, "Idempotency-Key": str(uuid4())},
        json={**payload, "preview_hash": preview.json()["preview_hash"]},
    )
    assert response.status_code == 201, response.text
    assert response.json()["reason"] == ""
    for item in response.json()["items"]:
        run = env["client"].get(f"/api/v1/runs/{item['run_id']}").json()
        assert run["reason"] == ""
        assert run["status"] == ("queued" if mode == "catalog" else "pending_approval")
