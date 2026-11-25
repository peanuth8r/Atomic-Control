"""Bound log retention without deleting audit, approvals or run evidence metadata."""

import argparse
import time

from sqlalchemy import select

from apps.api.app.config import Settings
from apps.api.app.db import factory, make_engine
from apps.api.app.models import Log, Run
from apps.api.app.services.common import audit

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=30)
    args = p.parse_args()
    if args.days < 1:
        p.error("retention must be at least one day")
    with factory(make_engine(Settings().database_url))() as db, db.begin():
        runs = db.scalars(select(Run).where(Run.updated_at < time.time() - args.days * 86400)).all()
        for run in runs:
            log = db.get(Log, run.id)
            if log:
                log.content = "[Expired under log retention policy]"
            if run.result:
                run.result = {**run.result, "stdout": "[Expired]", "stderr": "[Expired]"}
        audit(db, "administrator:retention", "logs.expire", "execution_logs", days=args.days, count=len(runs))
    print("Log retention applied; metadata and audit retained.")
