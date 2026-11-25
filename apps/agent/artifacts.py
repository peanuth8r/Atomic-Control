"""Versioned, bounded artifact verification shared by the server and agents."""

import hashlib
import io
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath
from uuid import UUID

import jwt

from apps.api.app.catalog.validation import parse_yaml
from apps.api.app.services.common import fingerprint

PROTOCOL = 1
MAX_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_FILES = 128
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_path(value: str) -> str:
    if not isinstance(value, str) or len(value) > 240 or not value.startswith("atomics/"):
        raise ValueError("Artifact paths must be bounded relative atomics paths")
    if any(ord(c) < 32 or c in '\\:<>"|?*' for c in value):
        raise ValueError("Unsupported artifact path")
    parts = value.split("/")
    if any(
        not p or p in {".", ".."} or p.endswith((" ", ".")) or p.split(".")[0].upper() in RESERVED
        for p in parts
    ):
        raise ValueError("Unsafe artifact path")
    if PurePosixPath(value).as_posix() != value:
        raise ValueError("Noncanonical artifact path")
    return value


def validate_manifest(value: dict) -> dict:
    if (
        set(value) != {"protocol", "guid", "technique", "revision", "definition_hash", "files"}
        or value["protocol"] != PROTOCOL
    ):
        raise ValueError("Unsupported artifact manifest")
    UUID(value["guid"])
    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value["technique"]):
        raise ValueError("Invalid technique")
    if not re.fullmatch(r"[a-f0-9]{40}", value["revision"]) or not re.fullmatch(
        r"[a-f0-9]{64}", value["definition_hash"]
    ):
        raise ValueError("Invalid immutable source binding")
    files = value["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Artifact file count exceeds limits")
    seen, total = set(), 0
    prefixes: dict[str, str] = {}
    definition_path = f"atomics/{value['technique']}/{value['technique']}.yaml"
    for item in files:
        if set(item) != {"path", "size", "sha256"}:
            raise ValueError("Invalid artifact file metadata")
        path = safe_path(item["path"])
        parts = path.split("/")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            if prefixes.get(prefix.casefold(), prefix) != prefix:
                raise ValueError("Artifact directory names differ only by case")
            prefixes[prefix.casefold()] = prefix
        if (
            re.fullmatch(r"atomics/T\d{4}(?:\.\d{3})?/T\d{4}(?:\.\d{3})?\.ya?ml", path)
            and path != definition_path
        ):
            raise ValueError("Bundle cannot contain another Atomic technique definition")
        if (
            path.casefold() in seen
            or type(item["size"]) is not int
            or not 0 <= item["size"] <= MAX_FILE_BYTES
        ):
            raise ValueError("Duplicate artifact path or oversized file")
        if not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ValueError("Invalid file digest")
        seen.add(path.casefold())
        total += item["size"]
    if definition_path.casefold() not in seen:
        raise ValueError("Selected Atomic definition is missing")
    if total > MAX_BYTES - 100_000:
        raise ValueError("Artifact expanded size exceeds limit")
    return value


def verify_descriptor(descriptor: dict, snapshot: dict, public_key: str):
    manifest = validate_manifest(descriptor["manifest"])
    claims = jwt.decode(
        descriptor["signature"],
        public_key,
        algorithms=["RS256"],
        audience="atomic-control-artifact",
        issuer="atomic-control",
        options={"require": ["iss", "aud", "manifest", "purpose"]},
    )
    if claims.get("purpose") != "artifact-manifest-v1" or claims["manifest"] != manifest:
        raise ValueError("Artifact signature mismatch")
    if descriptor["manifest_hash"] != fingerprint(manifest):
        raise ValueError("Artifact manifest hash mismatch")
    for key, field in [
        ("guid", "atomic_guid"),
        ("technique", "technique"),
        ("revision", "source_revision"),
        ("definition_hash", "content_sha256"),
    ]:
        if manifest[key] != snapshot[field]:
            raise ValueError("Artifact differs from approved snapshot")
    if (
        not re.fullmatch(r"[a-f0-9]{64}", descriptor["digest"])
        or type(descriptor["size"]) is not int
        or not 0 < descriptor["size"] <= MAX_BYTES
    ):
        raise ValueError("Invalid artifact archive binding")
    return manifest


def reject_links(path: Path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Artifact links and reparse points are forbidden")
    return info


def verify_payload(root: Path, snapshot: dict, public_key: str):
    manifest = verify_descriptor(snapshot["artifact"], snapshot, public_key)
    expected = {item["path"]: item for item in manifest["files"]}
    reject_links(root)
    actual = set()
    for path in root.rglob("*"):
        info = reject_links(path)
        if stat.S_ISDIR(info.st_mode):
            continue
        name = path.relative_to(root).as_posix()
        if not stat.S_ISREG(info.st_mode) or name not in expected:
            raise ValueError("Unexpected artifact content")
        entry = expected[name]
        if info.st_size != entry["size"] or sha256(path.read_bytes()) != entry["sha256"]:
            raise ValueError("Artifact file hash mismatch")
        actual.add(name)
    if actual != set(expected):
        raise ValueError("Artifact files are missing")
    definitions = parse_yaml(
        (root / f"atomics/{snapshot['technique']}/{snapshot['technique']}.yaml").read_text()
    )
    if (
        len(definitions) != 1
        or definitions[0] != snapshot["definition"]
        or fingerprint(definitions[0]) != snapshot["content_sha256"]
    ):
        raise ValueError("Packaged definition differs from approved test")


def extract(archive: Path, root: Path, snapshot: dict, public_key: str):
    manifest = verify_descriptor(snapshot["artifact"], snapshot, public_key)
    descriptor = snapshot["artifact"]
    if archive.stat().st_size != descriptor["size"] or sha256(archive.read_bytes()) != descriptor["digest"]:
        raise ValueError("Artifact archive hash mismatch")
    if root.exists() or root.is_symlink():
        raise ValueError("Artifact destination must be new")
    root.mkdir(mode=0o755)
    expected = {item["path"]: item for item in manifest["files"]}
    with zipfile.ZipFile(archive) as bundle:
        if bundle.comment != descriptor["manifest_hash"].encode():
            raise ValueError("Archive manifest binding mismatch")
        entries = bundle.infolist()
        if len(entries) != len(expected) or len({e.filename for e in entries}) != len(entries):
            raise ValueError("Unexpected archive entries")
        for entry in entries:
            name = safe_path(entry.filename)
            mode = entry.external_attr >> 16
            if (
                name not in expected
                or entry.compress_type != zipfile.ZIP_STORED
                or entry.flag_bits & 1
                or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
            ):
                raise ValueError("Unsupported archive entry")
            item = expected[name]
            if entry.file_size != item["size"] or entry.compress_size != entry.file_size:
                raise ValueError("Archive size mismatch")
            data = bundle.read(entry)
            if sha256(data) != item["sha256"]:
                raise ValueError("Archive file digest mismatch")
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with path.open("xb") as handle:
                handle.write(data)
            path.chmod(0o644)
    verify_payload(root, snapshot, public_key)


def payload_root(config: dict, job: dict) -> Path:
    return Path(config["state_root"]) / "downloads" / str(UUID(job["attempt_id"])) / "payload"


def catalog_root(config: dict, job: dict) -> Path:
    return payload_root(config, job) if job["snapshot"].get("artifact") else Path(config["catalog_root"])


def make_archive(files: dict[str, bytes], manifest: dict) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = fingerprint(manifest).encode()
        for path, data in sorted(files.items()):
            info = zipfile.ZipInfo(safe_path(path), date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    value = output.getvalue()
    if len(value) > MAX_BYTES:
        raise ValueError("Artifact exceeds size limit")
    return value
