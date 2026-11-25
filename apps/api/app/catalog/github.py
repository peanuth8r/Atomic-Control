"""Fetch only the official public repository; never extract or execute archive contents."""

import io
import re
import tarfile
import time
from urllib.parse import quote

import httpx

from .validation import MAX_FILE_BYTES, CatalogValidationError, parse_yaml

REPOSITORY = "redcanaryco/atomic-red-team"
MAX_ARCHIVE_BYTES = 250_000_000
MAX_YAML_BYTES = 30_000_000
ATOMIC_PATH = re.compile(r"[^/]+/atomics/(T\d{4}(?:\.\d{3})?)/(T\d{4}(?:\.\d{3})?)\.yaml$")


class GitHubError(ValueError):
    pass


def fetch_github(ref: str, token: str = "") -> tuple[str, list[dict], list[dict[str, str]]]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "AtomicControl/0.1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with httpx.Client(timeout=httpx.Timeout(30, connect=10), follow_redirects=False) as client:
        response = client.get(
            f"https://api.github.com/repos/{REPOSITORY}/commits/{quote(ref, safe='')}", headers=headers
        )
        if response.status_code in {403, 429}:
            raise GitHubError(
                "GitHub rate limit or access restriction. Retry later or configure a server-side GitHub token."
            )
        if response.status_code == 404:
            raise GitHubError("Branch, tag, or commit was not found in the official repository.")
        if response.status_code != 200:
            raise GitHubError("GitHub could not resolve this revision. Retry later.")
        sha = response.json().get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise GitHubError("GitHub returned an invalid commit identifier.")
        archive = io.BytesIO()
        deadline = time.monotonic() + 180
        # Credentials are deliberately never sent to the archive host. No redirects are followed.
        with client.stream(
            "GET",
            f"https://codeload.github.com/{REPOSITORY}/tar.gz/{sha}",
            headers={"User-Agent": "AtomicControl/0.1"},
        ) as download:
            if download.status_code != 200:
                raise GitHubError("GitHub archive download failed. Retry later.")
            for chunk in download.iter_bytes(64 * 1024):
                if archive.tell() + len(chunk) > MAX_ARCHIVE_BYTES or time.monotonic() > deadline:
                    raise GitHubError("Repository archive exceeded the download size or time limit.")
                archive.write(chunk)
    archive.seek(0)
    return sha, *read_archive(archive, deadline)


def read_archive(archive, deadline: float | None = None) -> tuple[list[dict], list[dict[str, str]]]:
    definitions, files = [], []
    seen = set()
    total_yaml = 0
    total_expanded = 0
    deadline = deadline or time.monotonic() + 180
    try:
        with tarfile.open(fileobj=archive, mode="r|gz") as members:
            for index, member in enumerate(members):
                total_expanded += member.size
                if index > 100_000 or total_expanded > 1_500_000_000 or time.monotonic() > deadline:
                    raise GitHubError("Archive exceeded its member, expanded-size or processing limit.")
                match = ATOMIC_PATH.fullmatch(member.name)
                if not match:
                    continue
                if (
                    match[1] != match[2]
                    or not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.size > MAX_FILE_BYTES
                ):
                    raise GitHubError("Archive contains an unsupported Atomic definition entry.")
                content_file = members.extractfile(member)
                if content_file is None:
                    raise GitHubError("Could not read an Atomic definition.")
                raw = content_file.read(MAX_FILE_BYTES + 1)
                total_yaml += len(raw)
                if total_yaml > MAX_YAML_BYTES:
                    raise GitHubError("Atomic YAML collection exceeds the size limit.")
                path = "/".join(member.name.split("/")[1:])
                try:
                    content = raw.decode("utf-8-sig")
                    parsed = parse_yaml(content)
                except (UnicodeError, CatalogValidationError) as exc:
                    raise GitHubError(
                        f"{path}: {str(exc) if isinstance(exc, CatalogValidationError) else 'invalid UTF-8'}"
                    ) from None
                files.append({"filename": path, "content": content})
                for definition in parsed:
                    guid = definition["auto_generated_guid"]
                    if guid in seen:
                        raise GitHubError("Duplicate Atomic GUID in GitHub catalog.")
                    seen.add(guid)
                    definitions.append({"definition": definition, "path": path})
        if not definitions:
            raise GitHubError("No Atomic YAML definitions were found in the repository archive.")
        return definitions, files
    except (tarfile.TarError, EOFError, OSError):
        raise GitHubError("GitHub returned an unreadable repository archive.") from None
