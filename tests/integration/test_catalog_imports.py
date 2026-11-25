import copy
import io
import tarfile
from uuid import uuid4

import httpx
import pytest
import yaml
from sqlalchemy import select

from apps.api.app.catalog.github import GitHubError, fetch_github, read_archive
from apps.api.app.models import AtomicTest, Run
from apps.api.app.models import TestApproval as Approval
from tests.support.fixtures import seed

ADMIN = {"X-Test-User": "admin"}
SHA = "a" * 40


def atomic_file(guid=None, name="Uploaded validation test", command="Write-Output 'validation fixture'"):
    guid = guid or str(uuid4())
    definition = {
        "attack_technique": "T1082",
        "display_name": "System Information Discovery",
        "atomic_tests": [
            {
                "name": name,
                "auto_generated_guid": guid,
                "description": "Catalog import fixture only",
                "supported_platforms": ["windows"],
                "executor": {
                    "name": "powershell",
                    "command": command,
                    "cleanup_command": "Write-Output 'cleanup'",
                    "elevation_required": False,
                },
            }
        ],
    }
    return guid, {"filename": "T1082.yaml", "content": yaml.safe_dump(definition)}


def stage(env, files, revision=SHA):
    return env["client"].post(
        "/api/v1/catalog/uploads", headers=ADMIN, json={"files": files, "source_revision": revision}
    )


def preview(env, record):
    response = env["client"].get(f"/api/v1/catalog/imports/{record['id']}", headers=ADMIN)
    assert response.status_code == 200, response.text
    return response.json()


def apply(env, record, replace=False):
    data = preview(env, record)
    return env["client"].post(
        f"/api/v1/catalog/imports/{record['id']}/confirm",
        headers=ADMIN,
        json={"preview_token": data["preview_token"], "replace_conflicts": replace},
    )


def test_yaml_upload_preview_then_import_merges_without_approval(env):
    guid, file = atomic_file()
    c = env["client"]
    record = stage(env, [file]).json()
    assert record["status"] == "ready"
    assert len(c.get("/api/v1/tests").json()["items"]) == 1
    diff = preview(env, record)
    assert diff["counts"]["added"] == 1 and diff["changes"][0]["after"]["executor"]["command"]
    assert apply(env, record).status_code == 200
    test = c.get(f"/api/v1/tests/{guid}").json()
    assert test["catalog_source"] == "upload" and not test["approved"] and test["execution_ready"]
    assert c.get("/api/v1/tests/11111111-1111-4111-8111-111111111111").json()["approved"]
    with env["app"].state.sessions() as db:
        assert not db.scalars(select(Run)).all()
    actions = [e["action"] for e in c.get("/api/v1/audit").json()["items"]]
    assert "catalog.yaml-staged" in actions and "catalog.import-confirmed" in actions


@pytest.mark.parametrize("role", ["viewer", "operator", "approver"])
def test_catalog_import_admin_only(env, role):
    _, file = atomic_file()
    c = env["client"]
    for method, path, payload in [
        ("GET", "/catalog/imports", None),
        ("POST", "/catalog/uploads", {"files": [file]}),
        ("POST", "/catalog/sync", {"ref": "master"}),
    ]:
        assert (
            c.request(method, "/api/v1" + path, headers={"X-Test-User": role}, json=payload).status_code
            == 403
        )


@pytest.mark.parametrize(
    "content",
    [
        "!!python/object/apply:os.system ['echo unsafe']",
        "attack_technique: T1082\nattack_technique: T1059",
        "value: &a [*a]",
        "atomic_tests: []",
        "- not-a-document",
    ],
)
def test_invalid_or_unsafe_yaml_never_enters_catalog(env, content):
    response = stage(env, [{"filename": "test.yaml", "content": content}])
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_atomic_yaml"
    assert env["client"].get("/api/v1/tests").json()["total"] == 1


def test_batch_duplicate_guids_and_unsafe_filenames_rejected(env):
    guid, file = atomic_file()
    response = stage(env, [file, {**file, "filename": "other.yaml"}])
    assert response.json()["error"]["code"] == "duplicate_guid"
    assert stage(env, [{**file, "filename": "../../test.yaml"}]).status_code == 422
    assert stage(env, [file, file]).json()["error"]["code"] == "duplicate_filename"


def test_unpinned_upload_is_browsable_but_cannot_be_approved(env):
    guid, file = atomic_file()
    record = stage(env, [file], revision=None).json()
    assert not record["pinned"]
    apply(env, record).raise_for_status()
    value = env["client"].get(f"/api/v1/tests/{guid}").json()
    assert not value["execution_ready"]
    response = env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": value["content_sha256"],
            "source_revision": value["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    )
    assert response.json()["error"]["code"] == "catalog_not_pinned"


def test_changed_definition_revokes_review_and_confirmation_idempotent(env):
    guid, file = atomic_file()
    first = stage(env, [file]).json()
    apply(env, first).raise_for_status()
    value = env["client"].get(f"/api/v1/tests/{guid}").json()
    env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": value["content_sha256"],
            "source_revision": value["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    ).raise_for_status()
    identical = stage(env, [file]).json()
    assert preview(env, identical)["counts"]["unchanged"] == 1
    apply(env, identical).raise_for_status()
    assert env["client"].get(f"/api/v1/tests/{guid}").json()["approved"]
    _, changed = atomic_file(guid, command="Write-Output 'updated fixture'")
    update = stage(env, [changed]).json()
    diff = preview(env, update)
    assert diff["counts"]["changed"] == 1 and diff["changes"][0]["previously_approved"]
    apply(env, update).raise_for_status()
    response = env["client"].post(
        f"/api/v1/catalog/imports/{update['id']}/confirm",
        headers=ADMIN,
        json={"preview_token": diff["preview_token"]},
    )
    assert response.status_code == 200
    assert not env["client"].get(f"/api/v1/tests/{guid}").json()["approved"]


def test_stale_preview_rejected_without_partial_import(env):
    _, first_file = atomic_file()
    second_guid, second_file = atomic_file()
    first = stage(env, [first_file]).json()
    stale = preview(env, first)
    second = stage(env, [second_file]).json()
    apply(env, second).raise_for_status()
    response = env["client"].post(
        f"/api/v1/catalog/imports/{first['id']}/confirm",
        headers=ADMIN,
        json={"preview_token": stale["preview_token"]},
    )
    assert response.json()["error"]["code"] == "preview_stale"
    assert env["client"].get("/api/v1/tests").json()["total"] == 2


def test_demo_restart_does_not_approve_or_remove_uploaded_tests(env):
    guid, file = atomic_file()
    apply(env, stage(env, [file]).json()).raise_for_status()
    seed(env["settings"])
    value = env["client"].get(f"/api/v1/tests/{guid}").json()
    assert value["active"] and not value["approved"] and not value["simulated"]


def test_legacy_fixture_guid_cannot_be_overwritten(env):
    with env["app"].state.sessions() as db, db.begin():
        db.get(AtomicTest, "11111111-1111-4111-8111-111111111111").simulated = True
    _, file = atomic_file("11111111-1111-4111-8111-111111111111")
    record = stage(env, [file]).json()
    assert preview(env, record)["counts"]["conflict"] == 1
    assert apply(env, record).json()["error"]["code"] == "catalog_conflict"
    assert apply(env, record, replace=True).json()["error"]["code"] == "legacy_fixture_conflict"


def mock_fetch(monkeypatch, files, revision=SHA):
    from apps.api.app.catalog.validation import parse_yaml

    definitions = [
        {"definition": d, "path": "atomics/T1082/T1082.yaml"}
        for file in files
        for d in parse_yaml(file["content"])
    ]
    monkeypatch.setattr(
        "apps.api.app.catalog.imports.fetch_github",
        lambda *_: (revision, copy.deepcopy(definitions), copy.deepcopy(files)),
    )


def test_github_sync_pins_revision_and_scopes_removed_definitions(env, monkeypatch):
    upload_guid, upload_file = atomic_file()
    apply(env, stage(env, [upload_file]).json()).raise_for_status()
    github_guid, github_file = atomic_file()
    mock_fetch(monkeypatch, [github_file])
    c = env["client"]
    first = c.post("/api/v1/catalog/sync", headers=ADMIN, json={"ref": "master"})
    assert first.status_code == 202
    record = preview(env, first.json())
    assert record["status"] == "ready" and record["revision"] == SHA
    apply(env, record).raise_for_status()
    replacement_guid, replacement_file = atomic_file()
    mock_fetch(monkeypatch, [replacement_file], "b" * 40)
    second = c.post("/api/v1/catalog/sync", headers=ADMIN, json={"ref": "release/tag"}).json()
    diff = preview(env, second)
    assert diff["counts"]["removed"] == 1
    apply(env, second).raise_for_status()
    assert not c.get(f"/api/v1/tests/{github_guid}").json()["active"]
    listed = {t["guid"] for t in c.get("/api/v1/tests").json()["items"]}
    assert github_guid not in listed and upload_guid in listed and replacement_guid in listed
    assert "11111111-1111-4111-8111-111111111111" in listed


def test_github_errors_persist_and_do_not_change_catalog(env, monkeypatch):
    def failed(*_):
        raise GitHubError("GitHub rate limit. Retry later.")

    monkeypatch.setattr("apps.api.app.catalog.imports.fetch_github", failed)
    record = env["client"].post("/api/v1/catalog/sync", headers=ADMIN, json={"ref": "master"}).json()
    value = preview(env, record)
    assert value["status"] == "failed" and "rate limit" in value["error"]
    assert env["client"].get("/api/v1/tests").json()["total"] == 1
    assert (
        env["client"].post("/api/v1/catalog/sync", headers=ADMIN, json={"ref": "../../private"}).status_code
        == 422
    )


def archive_bytes(file):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        raw = file["content"].encode()
        member = tarfile.TarInfo("atomic-red-team-sha/atomics/T1082/T1082.yaml")
        member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))
        # Unrelated executable payload is skipped, never extracted.
        payload = tarfile.TarInfo("atomic-red-team-sha/atomics/T1082/src/payload.exe")
        payload.size = 4
        archive.addfile(payload, io.BytesIO(b"mock"))
    return stream.getvalue()


def test_real_fetch_contract_pins_archive_and_never_leaks_token(monkeypatch):
    _, file = atomic_file()
    requests = []
    actual_client = httpx.Client

    def handle(request):
        requests.append(request)
        if request.url.host == "api.github.com":
            assert request.headers["Authorization"] == "Bearer server-only-token"
            return httpx.Response(200, json={"sha": SHA})
        assert str(request.url) == f"https://codeload.github.com/redcanaryco/atomic-red-team/tar.gz/{SHA}"
        assert "authorization" not in request.headers
        return httpx.Response(200, content=archive_bytes(file))

    monkeypatch.setattr(
        "apps.api.app.catalog.github.httpx.Client",
        lambda **kwargs: actual_client(transport=httpx.MockTransport(handle), **kwargs),
    )
    revision, definitions, files = fetch_github("master", "server-only-token")
    assert revision == SHA and len(definitions) == 1 and len(files) == 1
    assert len(requests) == 2


def test_archive_symlink_definition_is_rejected():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        member = tarfile.TarInfo("repo/atomics/T1082/T1082.yaml")
        member.type, member.linkname = tarfile.SYMTYPE, "/private/secret"
        archive.addfile(member)
    stream.seek(0)
    with pytest.raises(GitHubError):
        read_archive(stream)


def test_staging_quota_can_be_released_by_discard(env):
    records = [stage(env, [atomic_file()[1]]).json() for _ in range(5)]
    assert stage(env, [atomic_file()[1]]).json()["error"]["code"] == "staging_limit"
    env["client"].delete(f"/api/v1/catalog/imports/{records[0]['id']}", headers=ADMIN).raise_for_status()
    assert stage(env, [atomic_file()[1]]).status_code == 201


async def test_streamed_request_limit_without_content_length(env):
    async def body():
        for _ in range(3):
            yield b"x" * 100_000

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env["app"], client=("127.0.0.1", 10)), base_url="http://test"
    ) as client:
        response = await client.post("/api/v1/runs", content=body())
        assert response.status_code == 413


def test_approval_settings_change_invalidates_staged_preview(env):
    record = stage(env, [atomic_file()[1]]).json()
    staged_preview = preview(env, record)
    with env["app"].state.sessions() as db, db.begin():
        db.get(Approval, "11111111-1111-4111-8111-111111111111").risk_level = "high"
    response = env["client"].post(
        f"/api/v1/catalog/imports/{record['id']}/confirm",
        headers=ADMIN,
        json={"preview_token": staged_preview["preview_token"]},
    )
    assert response.json()["error"]["code"] == "preview_stale"


def test_cross_source_replacement_requires_confirmation_and_revokes_review(env, monkeypatch):
    guid, file = atomic_file()
    apply(env, stage(env, [file]).json()).raise_for_status()
    value = env["client"].get(f"/api/v1/tests/{guid}").json()
    env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": value["content_sha256"],
            "source_revision": value["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    ).raise_for_status()
    mock_fetch(monkeypatch, [file])
    record = env["client"].post("/api/v1/catalog/sync", headers=ADMIN, json={"ref": "master"}).json()
    assert preview(env, record)["counts"]["conflict"] == 1
    assert apply(env, record).json()["error"]["code"] == "catalog_conflict"
    apply(env, record, replace=True).raise_for_status()
    value = env["client"].get(f"/api/v1/tests/{guid}").json()
    assert value["catalog_source"] == "github" and not value["approved"]


def test_new_commit_revokes_review_for_unchanged_definition(env):
    guid, file = atomic_file()
    apply(env, stage(env, [file]).json()).raise_for_status()
    value = env["client"].get(f"/api/v1/tests/{guid}").json()
    env["client"].post(
        f"/api/v1/tests/{guid}/review",
        headers=ADMIN,
        json={
            "content_sha256": value["content_sha256"],
            "source_revision": value["revision"],
            "allowed_profiles": ["standard-user"],
            "risk_level": "low",
        },
    ).raise_for_status()
    update = stage(env, [file], revision="b" * 40).json()
    assert preview(env, update)["counts"]["revision_changed"] == 1
    apply(env, update).raise_for_status()
    assert not env["client"].get(f"/api/v1/tests/{guid}").json()["approved"]


def test_preview_token_cannot_confirm_a_different_staged_import(env):
    first = stage(env, [atomic_file()[1]]).json()
    second = stage(env, [atomic_file()[1]]).json()
    wrong_token = preview(env, first)["preview_token"]
    response = env["client"].post(
        f"/api/v1/catalog/imports/{second['id']}/confirm", headers=ADMIN, json={"preview_token": wrong_token}
    )
    assert response.json()["error"]["code"] == "preview_stale"
    assert env["client"].get("/api/v1/tests").json()["total"] == 1
