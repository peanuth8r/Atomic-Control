"""Isolated browser-test harness. Never imports a deployment environment or runs host commands."""

import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

import uvicorn

from tests.conftest import env
from tests.support.fixtures import fixture_result


def main():
    node = shutil.which("node")
    if not node:
        raise SystemExit("Node 22.12+ is required on PATH")
    with tempfile.TemporaryDirectory(prefix="atomic-browser-tests-") as folder:
        fixture = env.__wrapped__(Path(folder))
        app, client = fixture["app"], fixture["client"]
        original = app.dependency_overrides.copy()
        from apps.api.app.auth import human

        original_human = original[human]

        def identity(request: __import__("fastapi").Request):
            if (
                not request.cookies.get("atomic_test_user")
                and not request.headers.get("x-test-user")
                and not request.headers.get("authorization")
            ):
                request.scope["headers"].append((b"x-test-user", b"operator"))
            return original_human(request)

        app.dependency_overrides[human] = identity
        stop = threading.Event()

        def evidence_worker():
            while not stop.wait(0.25):
                try:
                    job = (
                        client.post("/api/v1/agents/jobs/claim", headers=fixture["agent"], json={})
                        .json()
                        .get("job")
                    )
                    if job:
                        client.post(
                            f"/api/v1/agents/jobs/{job['run_id']}/result",
                            headers=fixture["agent"],
                            json=fixture_result(job),
                        ).raise_for_status()
                    import time

                    from apps.api.app.models import Actor

                    with app.state.sessions() as db, db.begin():
                        db.get(Actor, fixture["actor"]).last_heartbeat = time.time()
                except Exception:
                    if not stop.is_set():
                        raise

        worker = threading.Thread(target=evidence_worker, daemon=True)
        worker.start()
        front = subprocess.Popen(
            [
                node,
                "apps/frontend/node_modules/vite/bin/vite.js",
                "apps/frontend",
                "--host",
                "127.0.0.1",
                "--port",
                "15173",
                "--strictPort",
            ],
            env={**os.environ, "ATOMIC_DEV_API_PORT": "18000"},
        )
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=18000, access_log=False))
        try:
            print("ISOLATED TEST FIXTURES ONLY: http://127.0.0.1:15173; no host commands", flush=True)
            server.run()
        finally:
            stop.set()
            worker.join(timeout=5)
            front.terminate()
            front.wait(timeout=10)


if __name__ == "__main__":
    main()
