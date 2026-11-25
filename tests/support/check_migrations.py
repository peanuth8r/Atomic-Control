"""Validate schema migrations only against a temporary isolated database."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from tests.support.bootstrap import configure_environment

configure_environment()

with tempfile.TemporaryDirectory(prefix="atomic-schema-tests-") as folder:
    env = {**os.environ, "ATOMIC_DATABASE_URL": "sqlite:///" + str(Path(folder) / "schema.db")}
    for arguments in [("upgrade", "head"), ("check",)]:
        subprocess.run([sys.executable, "-m", "alembic", *arguments], env=env, check=True)
