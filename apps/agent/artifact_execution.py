"""One-attempt download, durable result retry, and workspace removal. Never replays execution."""

import json
import os
import shutil
import threading
import time
from pathlib import Path
from uuid import UUID, uuid4

from .artifacts import extract, payload_root, reject_links
from .logging import error_fields, event


def persist(broker, job):
    if broker.config.get("os") == "linux":
        from .linux.security import write_json

        write_json(broker.journal, job)
    else:
        from .execution_broker import restrict_acl

        temp = broker.journal.with_name(".delivery-" + uuid4().hex)
        with temp.open("x") as file:
            json.dump(job, file)
            file.flush()
            os.fsync(file.fileno())
        restrict_acl(temp)
        temp.replace(broker.journal)


def stop_execution(broker, job):
    if broker.config.get("os") == "linux":
        from .linux.broker import stop_unit, unit_name

        stop_unit(unit_name(job["attempt_id"]))
    else:
        profile = next(
            p for p in broker.config["profiles"] if p["id"] == job["snapshot"]["execution_profile_id"]
        )
        from .windows_processes import open_existing, terminate_and_verify

        handle = getattr(broker, "containment", None) or open_existing(job["attempt_id"])
        try:
            broker.stop_task(profile)
            terminate_and_verify(handle)
        finally:
            if handle:
                handle.Close()
            broker.containment = None


def remove_tree(path):
    if path.exists() or path.is_symlink():
        reject_links(path)
        shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        raise RuntimeError("Downloaded files remain on disk")


def purge(broker, job):
    folder = payload_root(broker.config, job).parent
    if folder.parent.exists():
        reject_links(folder.parent)
    remove_tree(folder)
    if broker.config.get("os") == "linux":
        remove_tree(Path(broker.config["work_root"]) / str(UUID(job["attempt_id"])))
        remove_tree(broker.root / str(UUID(job["attempt_id"])))
    else:
        profile = broker.root / str(UUID(job["snapshot"]["execution_profile_id"]))
        for name in ("job.json", "lease.json"):
            (profile / name).unlink(missing_ok=True)
        output = profile / "output"
        if output.exists():
            reject_links(output)
            for entry in output.iterdir():
                if entry.is_symlink() or not entry.is_dir():
                    entry.unlink()
                else:
                    remove_tree(entry)


def report(broker, job):
    state = job["delivery_state"]
    if state.get("processes_stopped") is not True:
        stop_execution(broker, job)
        state["processes_stopped"] = True
        persist(broker, job)
    proof = {"attempt_id": job["attempt_id"], "fence": job["fence"]}
    try:
        broker.client.post(
            f"agents/jobs/{job['run_id']}/workspace",
            {**proof, "artifact_digest": job["snapshot"]["artifact"]["digest"], "status": "removing"},
        )
    except Exception:
        pass  # Disconnection must not retain payloads.
    try:
        purge(broker, job)
        state["workspace_status"] = "purged"
    except (OSError, ValueError, RuntimeError):
        state["workspace_status"] = "purge_failed"
    persist(broker, job)
    proof = {"attempt_id": job["attempt_id"], "fence": job["fence"]}
    broker.client.post(
        f"agents/jobs/{job['run_id']}/workspace",
        {
            **proof,
            "artifact_digest": job["snapshot"]["artifact"]["digest"],
            "status": state["workspace_status"],
        },
    )
    broker.client.post(f"agents/jobs/{job['run_id']}/result", state["result"])
    if state["workspace_status"] != "purged":
        raise RuntimeError("Downloaded file removal failed; actor is held")
    broker.journal.unlink()
    return state["result"]


def recover(broker):
    job = json.loads(broker.journal.read_text())
    state = job.get("delivery_state")
    if not state:
        return False
    if "result" not in state:
        # An execution ticket may have been issued, but no restart may launch the test again.
        interrupted = state["phase"] == "executing"
        state.update(
            phase="reporting",
            processes_stopped=not interrupted,
            result={
                "attempt_id": job["attempt_id"],
                "fence": job["fence"],
                "simulated": False,
                "status": "inconclusive" if interrupted else "failed",
                "identity": None,
                "exit_code": None,
                "stdout": "",
                "stderr": "Interrupted attempt recovered without re-execution",
                "started_at": state["started_at"],
                "finished_at": time.time(),
            },
        )
        persist(broker, job)
    report(broker, job)
    return True


def execute(broker, job, executor):
    from .execution_broker import restrict_acl, verify_job

    try:
        profile = verify_job(job, broker.config, broker.public_key, require_payload=False)
    except Exception as error:
        event("job.preparation_error", stage="verify_assignment", **error_fields(error))
        raise
    if broker.journal.exists() or broker.journal.is_symlink():
        raise RuntimeError("Unreconciled attempt prevents download")
    job["delivery_state"] = {"phase": "preparing", "started_at": time.time(), "processes_stopped": True}
    try:
        persist(broker, job)
    except Exception as error:
        event("job.preparation_error", stage="write_preparation_journal", **error_fields(error))
        raise
    state = job["delivery_state"]
    completed = threading.Event()
    errors = []
    deadline = time.monotonic() + broker.config.get("artifact_preparation_seconds", 300)
    proof = {"attempt_id": job["attempt_id"], "fence": job["fence"]}

    def heartbeat():
        try:
            from .job_client import heartbeat_payload

            broker.client.post("agents/heartbeat", heartbeat_payload(broker.config, job["run_id"]))
            response = broker.client.post(f"agents/jobs/{job['run_id']}/heartbeat", proof)
            if (
                response["cancel_requested"]
                or response["lease_expires_at"] <= time.time()
                or broker.stop.is_set()
            ):
                raise RuntimeError("Preparation cancelled or lease lost")
        except Exception as exc:
            errors.append(exc)

    def renew():
        while not completed.wait(5):
            heartbeat()
            if errors:
                return

    def tick():
        if errors or broker.stop.is_set() or time.monotonic() > deadline:
            raise RuntimeError("Preparation cancelled, disconnected, or timed out")

    thread = threading.Thread(target=renew, daemon=True)
    try:
        heartbeat()
        tick()
        root = payload_root(broker.config, job)
        root.parent.parent.mkdir(mode=0o755, exist_ok=True)
        reject_links(root.parent.parent)
        root.parent.mkdir(mode=0o700)
        if os.name == "nt":
            restrict_acl(root.parent.parent)
            restrict_acl(root.parent)
        archive = root.parent / "bundle.zip"
        thread.start()
        broker.client.download_artifact(job, archive, tick)
        tick()
        extract(archive, root, job["snapshot"], broker.public_key)
        if os.name == "nt":
            for entry in [root.parent.parent, root.parent, root, *root.rglob("*")]:
                restrict_acl(entry, profile["expected_sid"])
        elif broker.config.get("os") == "linux":
            import pwd

            account = pwd.getpwnam(profile["account"])
            root.parent.parent.chmod(0o755)
            for entry in [root.parent, root, *root.rglob("*")]:
                os.chown(entry, 0, account.pw_gid)
                entry.chmod(
                    0o750
                )  # Supporting binaries/scripts are readable/executable, never profile-writable.
        else:
            for entry in [root.parent.parent, root.parent, root, *root.rglob("*")]:
                entry.chmod(0o755 if entry.is_dir() else 0o644)
        archive.unlink()
        tick()
        updated = broker.client.post(f"agents/jobs/{job['run_id']}/ready", proof)["job"]
        updated["delivery_state"] = state
        job = updated
        completed.set()
        thread.join(timeout=25)
        tick()
        state.update(phase="executing", processes_stopped=False)
        persist(broker, job)
        result = executor(job)
        state.update(phase="reporting", processes_stopped=False, result=result)
        persist(broker, job)
        stop_execution(broker, job)
        state["processes_stopped"] = True
    except Exception as exc:
        if state.get("result") is not None:
            persist(broker, job)
            raise  # Preserve execution evidence while process containment needs recovery.
        # Retain all proof and evidence until acknowledged; never automatically execute again.
        if state["phase"] == "executing":
            stop_execution(broker, job)
        state.update(
            phase="reporting",
            processes_stopped=True,
            result={
                **proof,
                "simulated": False,
                "status": "inconclusive" if state["phase"] == "executing" else "failed",
                "identity": None,
                "exit_code": None,
                "stdout": "",
                "stderr": "Attempt stopped: " + type(exc).__name__,
                "started_at": state["started_at"],
                "finished_at": time.time(),
            },
        )
    finally:
        completed.set()
        if thread.ident:
            thread.join(timeout=25)
    persist(broker, job)
    return report(broker, job)


def check_orphans(broker):
    if broker.journal.exists() or broker.config.get("delivery_mode") != "on_demand":
        return
    root = broker.root / "downloads"
    if root.exists() and any(root.iterdir()):
        from .job_client import heartbeat_payload

        broker.client.post("agents/heartbeat", heartbeat_payload(broker.config))
        raise RuntimeError(
            "Orphaned download workspace requires administrator inspection; no test dispatched"
        )
