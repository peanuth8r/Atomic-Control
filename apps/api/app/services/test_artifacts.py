"""Central immutable bundles. Stored with the database and retained for historical cleanup."""

import base64
import io
import re
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import jwt
from sqlalchemy import select, text

from apps.agent.artifacts import MAX_BYTES, MAX_FILE_BYTES, make_archive, safe_path, sha256, validate_manifest

from ..catalog.github import MAX_ARCHIVE_BYTES, REPOSITORY
from ..catalog.serialization import definition_yaml
from ..errors import fail
from ..models import TestArtifact
from .common import audit, fingerprint


def suggested_assets(definition):
    def strings(value):
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for child in value.values() for s in strings(child)]
        if isinstance(value, list):
            return [s for child in value for s in strings(child)]
        return []

    text = "\n".join(strings(definition))
    values = {
        key: str(value.get("default", "")) for key, value in definition.get("input_arguments", {}).items()
    }
    # Expand only reviewed literal defaults, never shell expressions or code.
    for _ in range(5):
        previous = text
        for key, value in values.items():
            text = text.replace("#{" + key + "}", value)
        if previous == text:
            break
    paths = set()
    for match in re.finditer(r"#\{PathToAtomicsFolder\}[/\\]+([^\s\"'`;|&<>]+)", text):
        suffix = match[1].replace("\\\\", "/").replace("\\", "/")
        if any(c in suffix for c in "#$*?{}"):
            raise ValueError("Dynamic Atomic asset paths require a bounded literal dependency definition")
        paths.add(safe_path("atomics/" + suffix.rstrip(")],")))
    if "#{PathToAtomicsFolder}" in text and not paths:
        raise ValueError("Cannot resolve Atomic asset references into a bounded file list")
    return sorted(paths)


def fetch_assets(revision, paths, token):
    """Read selected regular files from the fixed official commit; never extract a repository."""
    if not paths:
        return {}
    received = io.BytesIO()
    deadline = time.monotonic() + 180
    with httpx.Client(timeout=httpx.Timeout(30, connect=10), follow_redirects=False) as client:
        # No credentials are sent to codeload. Source is always the official immutable commit.
        with client.stream(
            "GET",
            f"https://codeload.github.com/{REPOSITORY}/tar.gz/{revision}",
            headers={"User-Agent": "AtomicControl/0.1"},
        ) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes(65536):
                if received.tell() + len(chunk) > MAX_ARCHIVE_BYTES or time.monotonic() > deadline:
                    raise ValueError("Source archive exceeded download limits")
                received.write(chunk)
    received.seek(0)
    result, expanded = {}, 0
    with tarfile.open(fileobj=received, mode="r|gz") as archive:
        for index, member in enumerate(archive):
            expanded += member.size
            if index > 100_000 or expanded > 1_500_000_000 or time.monotonic() > deadline:
                raise ValueError("Source archive exceeded processing limits")
            relative = member.name.partition("/")[2]
            if relative not in paths:
                continue
            if not member.isfile() or member.size > MAX_FILE_BYTES or relative in result:
                raise ValueError("Unsupported source asset")
            file = archive.extractfile(member)
            if file is None:
                raise ValueError("Source asset is unreadable")
            result[relative] = file.read(MAX_FILE_BYTES + 1)
            if sum(len(data) for data in result.values()) > MAX_BYTES - 100_000:
                raise ValueError("Selected source assets exceed the bundle size limit")
    if set(result) != set(paths):
        raise ValueError("One or more declared assets are absent from the source commit")
    return result


def prepare(db, test, data, settings, subject):
    from ..catalog.validation import pinned

    if not test.active or test.simulated or not pinned(test.revision):
        fail("catalog_not_pinned", "A real test with an exact source commit is required")
    if test.content_hash != data.content_sha256 or test.revision != data.source_revision:
        fail("catalog_mismatch", "Refresh the definition before preparing its files")
    try:
        paths = {safe_path(path) for path in data.asset_paths}
        required = set(suggested_assets(test.definition))
        if not required <= paths:
            raise ValueError("Declared assets omit a referenced file: " + ", ".join(sorted(required - paths)))
        yaml_path = f"atomics/{test.technique}/{test.technique}.yaml"
        if yaml_path in paths:
            raise ValueError("The selected definition is generated separately")
        supplied = {}
        for item in data.files:
            path = safe_path(item.path)
            value = base64.b64decode(item.content_base64, validate=True)
            if path not in paths or path in supplied or len(value) > MAX_FILE_BYTES:
                raise ValueError("Invalid supplied asset")
            supplied[path] = value
        missing = paths - set(supplied)
        if missing and test.catalog_source != "github":
            raise ValueError("Upload each declared asset for a custom/local definition")
        if test.catalog_source == "github" and supplied:
            raise ValueError("Official source assets must come from their exact GitHub commit")
        # Do not hold the database write lock while fetching source files.
        db.commit()
        files = {**supplied, **fetch_assets(test.revision, missing, settings.github_token.get_secret_value())}
        files[yaml_path] = definition_yaml(test.definition)
        manifest = validate_manifest(
            {
                "protocol": 1,
                "guid": test.guid,
                "technique": test.technique,
                "revision": test.revision,
                "definition_hash": test.content_hash,
                "files": [
                    {"path": path, "size": len(value), "sha256": sha256(value)}
                    for path, value in sorted(files.items())
                ],
            }
        )
        archive = make_archive(files, manifest)
    except (ValueError, OSError, httpx.HTTPError, tarfile.TarError) as exc:
        message = (
            str(exc) if isinstance(exc, ValueError) else "Source download failed; no artifact was published"
        )
        fail("artifact_preparation_failed", message, 422)
    if db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))
    db.refresh(test, with_for_update=True)
    if not test.active or test.content_hash != data.content_sha256 or test.revision != data.source_revision:
        fail("catalog_mismatch", "Definition changed during preparation; refresh and prepare again")
    digest = sha256(archive)
    item = db.get(TestArtifact, digest)
    if item is None:
        signature = jwt.encode(
            {
                "iss": "atomic-control",
                "aud": "atomic-control-artifact",
                "purpose": "artifact-manifest-v1",
                "manifest": manifest,
            },
            Path(settings.signing_key_file).read_text(),
            algorithm="RS256",
        )
        descriptor = {
            "protocol": 1,
            "digest": digest,
            "size": len(archive),
            "manifest_hash": fingerprint(manifest),
            "manifest": manifest,
            "signature": signature,
        }
        item = TestArtifact(
            digest=digest,
            guid=test.guid,
            revision=test.revision,
            definition=test.definition,
            descriptor=descriptor,
            archive=archive,
            revoked=True,
        )
        db.add(item)
    test.artifact_digest = digest
    audit(
        db,
        subject,
        "artifact.prepared",
        digest,
        guid=test.guid,
        revision=test.revision,
        files=len(files),
        size=len(archive),
    )
    db.flush()
    return item


def artifact_for(db, test):
    item = db.get(TestArtifact, test.artifact_digest) if test.artifact_digest else None
    return (
        item
        if item and item.revision == test.revision and fingerprint(item.definition) == test.content_hash
        else None
    )


def require_artifact(db, test, review):
    item = artifact_for(db, test)
    if not item or not review.artifact or review.artifact != item.descriptor or item.revoked:
        fail("artifact_unapproved", "Required test files are unavailable for this approved revision")
    return item


def historical_context(db, run):
    """Original cleanup content, with a durable, revocable artifact approval."""
    item = db.get(TestArtifact, run.snapshot["artifact"]["digest"])
    if not item or item.revoked or not item.approval or item.descriptor != run.snapshot["artifact"]:
        fail("artifact_unapproved", "Original artifact approval is unavailable or revoked")
    test = SimpleNamespace(
        guid=item.guid,
        technique=item.definition["technique"],
        name=item.definition["name"],
        revision=item.revision,
        content_hash=fingerprint(item.definition),
        definition=item.definition,
        active=True,
        simulated=False,
        artifact_digest=item.digest,
    )
    return test, SimpleNamespace(**item.approval, artifact=item.descriptor)


def revoke_artifacts(db, guid):
    for item in db.scalars(select(TestArtifact).where(TestArtifact.guid == guid)):
        item.revoked = True
