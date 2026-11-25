"""Fixed Task Scheduler entry point. No command/action/account accepted on the CLI."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from .execution_broker import verify_job
from .identity_validation import IdentityMismatch, capture_identity, validate_identity


@dataclass
class Progress:
    started_at: float
    stage: str = "read_configuration"
    folder: Path | None = None
    identity: dict | None = None
    launch_attempted: bool = False


def run(config_file: Path, profile_id: str):
    progress = Progress(started_at=time.time())
    try:
        return execute(config_file, profile_id, progress)
    except Exception as error:
        if progress.folder is not None:
            # Never copy exception messages: they can contain a signed grant or
            # configuration data. Fixed stages, exception types and OS error
            # numbers identify the failure without retaining credentials.
            detail = f"Windows execution wrapper failed; stage={progress.stage}; error={type(error).__name__}"
            for name in ("winerror", "errno"):
                value = getattr(error, name, None)
                if isinstance(value, int):
                    detail += f"; {name}={value}"
            persist_result(
                progress.folder,
                {
                    "status": "inconclusive" if progress.launch_attempted else "failed",
                    "identity": progress.identity,
                    "started_at": progress.started_at,
                    "finished_at": time.time(),
                    "exit_code": None,
                    "stdout": "",
                    "stderr": detail,
                },
            )
        raise


def execute(config_file: Path, profile_id: str, progress: Progress):
    config = json.loads(config_file.read_text())
    folder = Path(config["state_root"]) / str(UUID(profile_id))
    progress.folder = folder
    progress.stage = "read_assignment"
    job = json.loads((folder / "job.json").read_text())
    progress.stage = "verify_signed_assignment"
    profile = verify_job(job, config, Path(config["public_key_file"]).read_text())
    if profile["id"] != profile_id:
        raise ValueError("Task profile mismatch")
    progress.stage = "verify_dispatch_lease"
    lease = json.loads((folder / "lease.json").read_text())
    if lease["attempt_id"] != job["attempt_id"] or lease["expires_at"] <= time.time():
        raise ValueError("Dispatch lease expired")
    started = time.time()
    progress.stage = "capture_execution_identity"
    identity = capture_identity(profile_id, profile["expected_sid"])
    progress.identity = identity
    progress.stage = "validate_execution_identity"
    try:
        identity = validate_identity(identity, profile)
        progress.identity = identity
    except IdentityMismatch:
        persist_result(
            folder,
            {
                "status": "failed",
                "identity": identity,
                "started_at": started,
                "finished_at": time.time(),
                "exit_code": None,
                "stdout": "",
                "stderr": "Identity verification failed before Atomic invocation",
            },
        )
        return
    # Only the bundled fixed script path and validated read-only job file are passed.
    wrapper = Path(__file__).parent / "powershell" / "invoke_approved_atomic.ps1"
    progress.stage = "verify_powershell_path"
    if not Path(config["powershell_path"]).is_file():
        raise FileNotFoundError("Configured PowerShell executable is unavailable")
    progress.stage = "verify_invoke_module_path"
    module = Path(config["invoke_module_path"])
    if not module.is_file():
        raise FileNotFoundError("Configured Invoke-AtomicRedTeam module is unavailable")
    progress.stage = "verify_invoke_module_pin"
    expected_hash = config.get("invoke_module_sha256", "")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_hash):
        raise ValueError("Configure the reviewed Invoke-AtomicRedTeam module hash")
    progress.stage = "verify_invoke_module_hash"
    if hashlib.sha256(module.read_bytes()).hexdigest() != expected_hash.lower():
        raise ValueError("Invoke-AtomicRedTeam module hash mismatch")
    containment = None
    if job["snapshot"].get("artifact"):
        from .windows_processes import JoinError, join

        progress.stage = "join_process_containment"
        try:
            containment = join(job["attempt_id"])
        except JoinError as error:
            progress.stage = error.stage
            raise
    # Keep the containment handle alive until this fixed wrapper process exits.
    assert containment is not None or not job["snapshot"].get("artifact")
    command = [
        config["powershell_path"],
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(wrapper),
        "-JobFile",
        str(folder / "job.json"),
        "-ConfigFile",
        str(config_file),
    ]
    progress.stage = "open_output_files"
    with (
        (folder / "output" / "stdout.tmp").open("w+b") as out,
        (folder / "output" / "stderr.tmp").open("w+b") as err,
    ):
        # Output lives on a provisioning-time quota-limited volume; truncate before reporting.
        progress.stage = "launch_powershell"
        # An exception during process creation does not prove that no process
        # started. Preserve uncertainty from this point until a result exists.
        progress.launch_attempted = True
        process = subprocess.Popen(command, stdout=out, stderr=err)
        progress.stage = "collect_execution_result"
        status = "failed"
        deadline = time.monotonic() + job["snapshot"]["timeout_seconds"]
        try:
            while process.poll() is None:
                lease = json.loads((folder / "lease.json").read_text())
                if (
                    lease["expires_at"] <= time.time()
                    or time.monotonic() >= deadline
                    or os.fstat(out.fileno()).st_size > 65536
                    or os.fstat(err.fileno()).st_size > 65536
                ):
                    subprocess.run(
                        ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                        capture_output=True,
                        check=False,
                    )
                    status = "timed_out" if time.monotonic() >= deadline else "inconclusive"
                    break
                time.sleep(0.2)
            else:
                status = "succeeded" if process.returncode == 0 else "failed"
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                subprocess.run(
                    ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False
                )
        out.seek(0)
        err.seek(0)
        result = {
            "status": status,
            "identity": identity,
            "started_at": started,
            "finished_at": time.time(),
            "exit_code": process.returncode,
            "stdout": out.read(65536).decode("utf-8", errors="replace"),
            "stderr": err.read(65536).decode("utf-8", errors="replace"),
            "prerequisites": {
                "status": "passed" if process.returncode == 0 else "missing_or_failed",
                "details_in_logs": True,
            }
            if job["snapshot"]["action"] == "check"
            else None,
        }
    evidence_file = folder / "output" / "atomic-evidence.json"
    if (
        job["snapshot"]["action"] == "check"
        and evidence_file.exists()
        and evidence_file.stat().st_size <= 65536
    ):
        result["prerequisites"] = json.loads(evidence_file.read_text(encoding="utf-8-sig"))
    progress.stage = "persist_execution_result"
    persist_result(folder, result)


def persist_result(folder: Path, result: dict):
    temp = folder / "output" / "result.tmp"
    temp.write_text(json.dumps(result))
    temp.replace(folder / "output" / "result.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--profile-id", required=True)
    args = parser.parse_args()
    run(args.config, args.profile_id)
