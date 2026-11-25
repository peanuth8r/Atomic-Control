"""Explicit administrator action to apply an exact reviewed allowlist. Never called on import/install."""

import argparse
from pathlib import Path
from uuid import UUID

import yaml

from apps.api.app.catalog.parser import execution_platforms
from apps.api.app.config import Settings
from apps.api.app.db import factory, make_engine
from apps.api.app.models import AtomicTest, TestApproval
from apps.api.app.services.common import audit


def apply(db, manifest: dict):
    for entry in manifest["approved_tests"]:
        guid = str(UUID(entry["guid"]))
        test = db.get(AtomicTest, guid)
        if (
            not test
            or test.content_hash != entry["content_sha256"]
            or test.revision != entry["source_revision"]
        ):
            raise ValueError("Manifest hash/revision does not match imported definition: " + guid)
        profiles, platforms = entry["allowed_profiles"], entry["allowed_platforms"]
        if (
            not profiles
            or set(profiles) - {"standard-user", "local-admin"}
            or not platforms
            or set(platforms) - set(execution_platforms(test.definition))
        ):
            raise ValueError("Unsupported manifest platform/profile")
        if entry["risk_level"] not in {"low", "medium", "high"}:
            raise ValueError("Invalid manifest risk")
        db.merge(
            TestApproval(
                guid=guid,
                content_hash=test.content_hash,
                revision=test.revision,
                allowed_profiles=profiles,
                allowed_platforms=platforms,
                risk_level=entry["risk_level"],
                approved_by="administrator:manifest",
                approved=entry["approved"] is True,
            )
        )
        audit(
            db,
            "administrator:manifest",
            "catalog.manifest-review",
            guid,
            content_sha256=test.content_hash,
            approved=entry["approved"] is True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    with factory(make_engine(Settings().database_url))() as db, db.begin():
        apply(db, yaml.safe_load(args.manifest.read_text()))
    print("Exact reviewed manifest applied. No test executed.")
