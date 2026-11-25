"""Append-only unapproved catalog creation; never approves content or dispatches work."""

import base64

from sqlalchemy import select

from apps.agent.artifacts import MAX_BYTES, MAX_FILE_BYTES, safe_path, sha256, validate_manifest

from ..catalog.imports import lock_catalog
from ..catalog.serialization import definition_yaml
from ..catalog.validation import CatalogValidationError, parse_yaml
from ..errors import fail
from ..models import AtomicTest, CustomTestSubmission, Revision, SourceBlob
from .common import audit, fingerprint


def receipt(item, replayed=False):
    return {
        "id": item.id,
        "revision": item.revision,
        "submitted_by": item.submitted_by,
        "created_at": item.created_at,
        "tests": item.tests,
        "files": item.files,
        "replayed": replayed,
    }


def submit(db, principal, data, key):
    principal.require("operator")
    if principal.mcp and "atomic:request" not in principal.scopes:
        fail("insufficient_scope", "Custom submissions require atomic:request", 403)
    if not key or not key.strip() or len(key) > 128:
        fail("idempotency_required", "A 1–128 character Idempotency-Key is required", 422)
    state = lock_catalog(db)
    hashed = fingerprint(data.model_dump(mode="json"))
    previous = db.scalar(
        select(CustomTestSubmission).where(
            CustomTestSubmission.submitted_by == principal.subject,
            CustomTestSubmission.idempotency_key == key,
        )
    )
    if previous:
        if previous.request_hash != hashed:
            fail("idempotency_conflict", "Key already used for a different custom submission")
        return receipt(previous, True)
    try:
        definitions = parse_yaml(data.content)
    except UnicodeError:
        fail("invalid_atomic_yaml", "YAML must be valid UTF-8 text", 422)
    except CatalogValidationError as error:
        fail("invalid_atomic_yaml", str(error), 422)
    if len(definitions) > 100:
        fail("custom_test_limit", "Submit at most 100 tests in one YAML document", 422)
    conflicts = list(
        db.scalars(
            select(AtomicTest.guid).where(
                AtomicTest.guid.in_([d["auto_generated_guid"] for d in definitions])
            )
        )
    )
    if conflicts:
        fail("custom_guid_conflict", "Existing test GUIDs cannot be overwritten; assign new GUIDs", 409)
    files = {}
    technique = definitions[0]["technique"]
    yaml_path = f"atomics/{technique}/{technique}.yaml"
    try:
        for item in data.files:
            path = safe_path(item.path)
            if path in files or not path.startswith(f"atomics/{technique}/") or path == yaml_path:
                raise ValueError("Supporting files must have unique paths under the selected technique")
            raw = base64.b64decode(item.content_base64, validate=True)
            if len(raw) > MAX_FILE_BYTES:
                raise ValueError("Supporting file exceeds the 16 MiB limit")
            files[path] = raw
        folded = {yaml_path.casefold(), *(path.casefold() for path in files)}
        for path in files:
            parts = path.split("/")
            if any("/".join(parts[:index]).casefold() in folded for index in range(1, len(parts))):
                raise ValueError("Supporting files cannot also be parent directories")
        if sum(len(raw) for raw in files.values()) + len(data.content.encode()) > MAX_BYTES - 100_000:
            raise ValueError("Custom source exceeds the bundle size limit")
    except ValueError as error:
        fail("invalid_custom_file", str(error), 422)
    manifest = [
        {"path": path, "size": len(raw), "sha256": sha256(raw)} for path, raw in sorted(files.items())
    ]
    # Protocol-v1 revisions are 40 hex characters. This is an immutable content
    # identifier, explicitly marked custom, never an asserted GitHub commit.
    revision = fingerprint(
        {"kind": "custom-tests-v1", "filename": data.filename, "definitions": definitions, "files": manifest}
    )[:40]
    try:
        for definition in definitions:
            raw = definition_yaml(definition)
            validate_manifest(
                {
                    "protocol": 1,
                    "guid": definition["auto_generated_guid"],
                    "technique": technique,
                    "revision": revision,
                    "definition_hash": fingerprint(definition),
                    "files": [*manifest, {"path": yaml_path, "size": len(raw), "sha256": sha256(raw)}],
                }
            )
    except ValueError as error:
        fail("invalid_custom_file", str(error), 422)
    if not db.get(Revision, revision):
        db.add(Revision(id=revision))
        db.flush()
    tests = []
    for definition in definitions:
        guid = definition["auto_generated_guid"]
        digest = fingerprint(definition)
        db.add(
            AtomicTest(
                guid=guid,
                technique=definition["technique"],
                name=definition["name"],
                revision=revision,
                content_hash=digest,
                definition=definition,
                simulated=False,
                catalog_source="custom",
                source_path=data.filename,
                active=True,
            )
        )
        tests.append(
            {
                "guid": guid,
                "name": definition["name"],
                "technique": definition["technique"],
                "content_sha256": digest,
            }
        )
    for raw in files.values():
        digest = sha256(raw)
        blob = db.get(SourceBlob, digest)
        if blob is None:
            db.add(SourceBlob(digest=digest, content=raw))
            db.flush()
        elif blob.content != raw:
            fail("custom_source_corrupt", "Retained supporting-file content failed verification", 409)
    item = CustomTestSubmission(
        submitted_by=principal.subject,
        idempotency_key=key,
        request_hash=hashed,
        revision=revision,
        filename=data.filename,
        tests=tests,
        files=manifest,
    )
    db.add(item)
    state.generation += 1
    db.flush()
    audit(
        db,
        principal.subject,
        "catalog.custom-submitted",
        item.id,
        revision=revision,
        tests=len(tests),
        files=len(files),
    )
    return receipt(item)


def submitted_files(db, test):
    if test.catalog_source != "custom":
        return []
    submission = db.scalar(select(CustomTestSubmission).where(CustomTestSubmission.revision == test.revision))
    if not submission or not any(
        item["guid"] == test.guid and item["content_sha256"] == test.content_hash for item in submission.tests
    ):
        fail("custom_source_unavailable", "Custom source no longer matches its submission", 409)
    return submission.files


def retained_files(db, test, paths):
    result = {}
    for entry in submitted_files(db, test):
        if entry["path"] not in paths:
            continue
        blob = db.get(SourceBlob, entry["sha256"])
        if blob is None or len(blob.content) != entry["size"] or sha256(blob.content) != entry["sha256"]:
            fail("custom_source_unavailable", "Submitted supporting files are missing or changed", 409)
        result[entry["path"]] = blob.content
    return result
