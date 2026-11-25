import subprocess
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import AtomicTest, Revision, TestApproval
from ..services.common import fingerprint

PLATFORM_EXECUTORS = {"windows": {"powershell", "command_prompt"}, "linux": {"bash", "sh"}}
ALLOWED_EXECUTORS = set().union(*PLATFORM_EXECUTORS.values())


def execution_platforms(definition: dict) -> list[str]:
    return [
        platform
        for platform, executors in PLATFORM_EXECUTORS.items()
        if platform in definition.get("supported_platforms", [])
        and definition.get("executor", {}).get("name") in executors
        and (
            platform != "linux"
            or not definition.get("dependencies")
            or definition.get("dependency_executor_name", definition["executor"]["name"]) in executors
        )
    ]


def parse_file(path: Path) -> list[dict]:
    from .validation import MAX_FILE_BYTES, parse_yaml

    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Catalog file exceeds size limit")
    return parse_yaml(path.read_text(encoding="utf-8-sig"))


def import_catalog(db: Session, root: Path, revision: str):
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"], text=True
    )
    if actual != revision or dirty:
        raise ValueError("Catalog must be a clean, pinned local repository")
    if not db.get(Revision, revision):
        db.add(Revision(id=revision))
        db.flush()
    seen = set()
    for path in sorted(root.rglob("T*.yaml")):
        for definition in parse_file(path):
            guid = definition["auto_generated_guid"]
            if guid in seen:
                raise ValueError("Duplicate Atomic GUID")
            seen.add(guid)
            item = db.get(AtomicTest, guid)
            content_hash = fingerprint(definition)
            if item is None:
                item = AtomicTest(guid=guid)
                db.add(item)
            item.technique = definition["technique"]
            item.name = definition["name"]
            item.revision = revision
            item.content_hash = content_hash
            item.definition = definition
            item.simulated = False
            item.catalog_source = "local"
            item.source_path = path.relative_to(root).as_posix()
            item.active = True
            approval = db.get(TestApproval, guid)
            if approval and (approval.content_hash != content_hash or approval.revision != revision):
                approval.approved = False
    # Removed definitions lose approval too.
    for item in db.query(AtomicTest).all():
        if item.guid not in seen and item.catalog_source == "local" and not item.simulated:
            item.active = False
            approval = db.get(TestApproval, item.guid)
            if approval:
                approval.approved = False


def approved(db, test: AtomicTest) -> TestApproval | None:
    return valid_review(test, db.get(TestApproval, test.guid))


def valid_review(test: AtomicTest, review: TestApproval | None) -> TestApproval | None:
    from .validation import pinned

    if (
        (not test.simulated and pinned(test.revision))
        and test.active
        and review
        and review.approved
        and review.content_hash == test.content_hash
        and review.revision == test.revision
    ):
        return review
    return None
