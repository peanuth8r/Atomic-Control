"""Windows signed-profile protocol; synthetic token evidence, no host commands."""

import pytest
from sqlalchemy import select

from apps.agent.job_client import heartbeat_payload
from apps.agent.profile_config import verify_manifest
from apps.api.app.models import Actor, Profile
from tests.integration.test_profile_sync import sync as sync


@pytest.fixture
def windows(sync):
    s = sync
    s["config"].update(os="windows", os_version="Windows")
    s["profile"].update(expected_sid="S-1-5-21-111-222-333-1001", logon_type="batch")
    with s["app"].state.sessions() as db, db.begin():
        db.get(Actor, s["actor"]).os = "windows"
        profile = db.get(Profile, s["profile"]["id"])
        profile.expected_sid, profile.logon_type = s["profile"]["expected_sid"], "batch"
    return s


def heartbeat(s):
    response = s["client"].post(
        "/api/v1/agents/heartbeat", headers=s["agent"], json=heartbeat_payload(s["config"])
    )
    assert response.status_code == 200, response.text


def manifest(s):
    response = s["client"].post("/api/v1/agents/profile-sync/poll", headers=s["agent"])
    assert response.status_code == 200, response.text
    return verify_manifest(response.json()["manifest"], s["config"], s["public"])


def evidence(p):
    elevated = p["privilege"] == "elevated"
    return {
        "platform": "windows",
        "expected_profile_id": p["id"],
        "expected_account_sid": p["expected_sid"],
        "actual_account_sid": p["expected_sid"],
        "actual_account_name": p["account"],
        "elevated": elevated,
        "admin_member": elevated,
        "admin_enabled": elevated,
        "integrity_level": "high" if elevated else "medium",
        "process_id": 123,
        "verified": True,
    }


def ack(s, claims, results=None):
    return s["client"].post(
        f"/api/v1/agents/profile-sync/{claims['jti']}/result",
        headers=s["agent"],
        json={
            "generation": claims["generation"],
            "payload_hash": claims["payload_hash"],
            "error": "",
            "results": results
            if results is not None
            else {
                p["id"]: {"healthy": True, "identity": evidence(p), "error": ""}
                for p in claims["payload"]["profiles"]
            },
        },
    )


def test_windows_additions_are_signed_and_validate_real_token_shape(windows):
    s = windows
    heartbeat(s)
    first = manifest(s)
    assert first["payload"]["os"] == "windows"
    assert ack(s, first).json()["status"] == "applied"
    response = s["client"].post(
        f"/api/v1/actors/{s['actor']}/profiles",
        json={
            "profile_key": "local-admin",
            "account": "admin-user",
            "expected_sid": "S-1-5-21-111-222-333-1002",
            "display_name": "Admin",
            "privilege": "elevated",
        },
    )
    assert response.status_code == 200, response.text
    second = manifest(s)
    assert second["generation"] == first["generation"] + 1
    assert len(second["payload"]["profiles"]) == 2
    assert ack(s, second).json()["status"] == "applied"
    with s["app"].state.sessions() as db:
        assert all(p.healthy for p in db.scalars(select(Profile)))


def test_missing_windows_task_is_actionable_and_cannot_mark_healthy(windows):
    s = windows
    heartbeat(s)
    claims = manifest(s)
    results = {s["profile"]["id"]: {"healthy": False, "identity": None, "error": "task_missing"}}
    response = ack(s, claims, results)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "validation_failed"
    assert s["client"].post(f"/api/v1/actors/{s['actor']}/profile-sync").status_code == 200
    assert manifest(s)["generation"] == claims["generation"] + 1


@pytest.mark.parametrize("mutation", ["admin_as_standard", "wrong_sid", "linux_evidence"])
def test_windows_receipt_rejects_wrong_identity(windows, mutation):
    s = windows
    heartbeat(s)
    claims = manifest(s)
    item = evidence(s["profile"])
    if mutation == "admin_as_standard":
        item["admin_member"] = True
    elif mutation == "wrong_sid":
        item["actual_account_sid"] = "S-1-5-21-111-222-333-1999"
    else:
        from tests.integration.test_profile_sync import evidence as linux_evidence

        item = linux_evidence({**s["profile"], "expected_sid": "uid:1001"})
    response = ack(s, claims, {s["profile"]["id"]: {"healthy": True, "identity": item, "error": ""}})
    assert response.status_code == 422, response.text


def test_windows_deletion_sync_delivers_empty_desired_state(windows):
    s = windows
    heartbeat(s)
    first = manifest(s)
    assert ack(s, first).status_code == 200
    response = s["client"].delete(f"/api/v1/actors/{s['actor']}/profiles/{s['profile']['id']}")
    assert response.status_code == 200, response.text
    empty = manifest(s)
    assert empty["payload"]["profiles"] == []
    assert ack(s, empty).json()["status"] == "applied"
    assert s["client"].get(f"/api/v1/actors/{s['actor']}/profiles").json() == []
