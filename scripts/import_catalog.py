import argparse
from pathlib import Path

from apps.api.app.catalog.parser import import_catalog
from apps.api.app.config import Settings
from apps.api.app.db import factory, make_engine
from apps.api.app.services.common import audit

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Import a clean local pinned catalog without approving tests")
    p.add_argument("root", type=Path)
    p.add_argument("revision")
    args = p.parse_args()
    with factory(make_engine(Settings().database_url))() as db, db.begin():
        import_catalog(db, args.root, args.revision)
        audit(db, "administrator:local-cli", "catalog.import", args.revision)
    print("Imported. Definitions remain unapproved until exact-hash review.")
