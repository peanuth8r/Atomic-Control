import time
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import Principal, human
from ..catalog.github import REPOSITORY
from ..catalog.imports import apply_stage, fetch_stage, lock_catalog, preview, status_view
from ..catalog.schemas import ConfirmImport, GitHubSync, ImportPreview, ImportStatus, YAMLUpload
from ..catalog.validation import CatalogValidationError, parse_yaml
from ..db import session
from ..errors import fail
from ..models import CatalogImport
from ..services.common import audit, fingerprint

router = APIRouter(prefix="/api/v1/catalog", tags=["Catalog administration"])


def administrator(p: Principal = Depends(human)) -> Principal:
    p.require("administrator")
    return p


def stage_record(db, import_id):
    item = db.get(CatalogImport, str(import_id), with_for_update=True)
    if not item:
        fail("not_found", "Catalog import does not exist", 404)
    status_view(item)
    return item


def staging_quota(db):
    lock_catalog(db)
    open_imports = db.scalars(
        select(CatalogImport).where(CatalogImport.status.in_(["fetching", "ready"]))
    ).all()
    for item in open_imports:
        status_view(item)
    if (
        sum(i.status in {"fetching", "ready"} and i.created_at > time.time() - 86400 for i in open_imports)
        >= 5
    ):
        fail("staging_limit", "Five imports are already staged. Confirm or discard one before continuing")


@router.get("/source")
def source(p: Principal = Depends(administrator)):
    return {
        "repository": REPOSITORY,
        "url": f"https://github.com/{REPOSITORY}/tree/master/atomics",
        "upload_max_bytes": 4_000_000,
        "file_max_bytes": 1_000_000,
        "max_files": 50,
    }


@router.get("/imports", response_model=list[ImportStatus])
def history(db: Session = Depends(session), p: Principal = Depends(administrator)):
    return [
        status_view(i)
        for i in db.scalars(select(CatalogImport).order_by(CatalogImport.created_at.desc()).limit(20))
    ]


@router.post("/sync", response_model=ImportStatus, status_code=202)
def sync(
    data: GitHubSync,
    request: Request,
    tasks: BackgroundTasks,
    db: Session = Depends(session),
    p: Principal = Depends(administrator),
):
    staging_quota(db)
    if db.scalar(select(CatalogImport).where(CatalogImport.status == "fetching")):
        fail("sync_in_progress", "A GitHub sync is already in progress")
    staged = CatalogImport(source="github", ref=data.ref, created_by=p.subject)
    db.add(staged)
    db.flush()
    audit(db, p.subject, "catalog.sync-requested", staged.id, ref=data.ref)
    value = status_view(staged)
    # Release transaction before network work; commit explicitly before starting background fetch.
    db.commit()
    tasks.add_task(
        fetch_stage,
        request.app.state.sessions,
        staged.id,
        request.app.state.settings.github_token.get_secret_value(),
    )
    return value


@router.post("/uploads", response_model=ImportStatus, status_code=201)
def upload(data: YAMLUpload, db: Session = Depends(session), p: Principal = Depends(administrator)):
    staging_quota(db)
    if sum(len(f.content.encode("utf-8")) for f in data.files) > 4_000_000:
        fail("upload_too_large", "Combined YAML content exceeds 4 MB", 413)
    definitions, files, seen, filenames = [], [], set(), set()
    for file in data.files:
        if file.filename in filenames:
            fail("duplicate_filename", "Each uploaded filename must be unique", 422)
        filenames.add(file.filename)
        try:
            parsed = parse_yaml(file.content)
        except CatalogValidationError as exc:
            fail("invalid_atomic_yaml", f"{file.filename}: {exc}", 422)
        files.append(file.model_dump())
        for definition in parsed:
            guid = definition["auto_generated_guid"]
            if guid in seen:
                fail("duplicate_guid", "Duplicate Atomic GUID across uploaded files", 422)
            seen.add(guid)
            definitions.append({"definition": definition, "path": file.filename})
    revision = data.source_revision or "upload-" + fingerprint(
        sorted(definitions, key=lambda x: x["definition"]["auto_generated_guid"])
    )
    staged = CatalogImport(
        source="upload",
        ref=", ".join(f.filename for f in data.files)[:128],
        revision=revision,
        created_by=p.subject,
        status="ready",
        definitions=definitions,
        files=files,
    )
    db.add(staged)
    db.flush()
    audit(db, p.subject, "catalog.yaml-staged", staged.id, count=len(definitions), files=len(files))
    return status_view(staged)


@router.get("/imports/{import_id}", response_model=ImportPreview)
def details(
    import_id: UUID,
    limit: int = Query(30, ge=1, le=100),
    offset: int = Query(0, ge=0),
    kind: str = "",
    db: Session = Depends(session),
    p: Principal = Depends(administrator),
):
    staged = stage_record(db, import_id)
    counts, changes, token = preview(db, staged) if staged.status == "ready" else ({}, [], "0" * 64)
    if kind:
        changes = [c for c in changes if c["kind"] == kind]
    return {
        **status_view(staged),
        "counts": counts,
        "changes": changes[offset : offset + limit],
        "total": len(changes),
        "preview_token": token,
        "limit": limit,
        "offset": offset,
    }


@router.post("/imports/{import_id}/confirm", response_model=ImportStatus)
def confirm(
    import_id: UUID,
    data: ConfirmImport,
    db: Session = Depends(session),
    p: Principal = Depends(administrator),
):
    staged = stage_record(db, import_id)
    apply_stage(db, staged, data.preview_token, p.subject, data.replace_conflicts)
    return status_view(staged)


@router.delete("/imports/{import_id}")
def discard(import_id: UUID, db: Session = Depends(session), p: Principal = Depends(administrator)):
    staged = stage_record(db, import_id)
    if staged.status == "imported":
        fail("already_imported", "Imported history is retained for auditing")
    audit(db, p.subject, "catalog.preview-discarded", staged.id)
    db.delete(staged)
    return {"discarded": True}
