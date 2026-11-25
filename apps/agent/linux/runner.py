"""Fixed systemd unit entry point. Revalidates the signed job before invoking a shell."""

import argparse
import json
import os
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

from ..artifacts import catalog_root
from ..execution_broker import verify_job
from .commands import commands
from .identity import capture_identity, validate_identity
from .security import protected


def run_commands(plan: list[list[str]], timeout: float, work: Path) -> tuple[str, int | None, str, str]:
    deadline = time.monotonic() + timeout
    output = [bytearray(), bytearray()]
    status, code = "succeeded", 0
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": str(work)}
    for command in plan:
        process = subprocess.Popen(
            command,
            cwd=work,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        assert process.stdout and process.stderr
        selector.register(process.stdout, selectors.EVENT_READ, 0)
        selector.register(process.stderr, selectors.EVENT_READ, 1)
        try:
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    status = "timed_out"
                    break
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    stream = output[key.data]
                    remaining = 65536 - len(stream)
                    stream.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        status = "inconclusive"
                        break
                if status != "succeeded":
                    break
            if status == "succeeded":
                code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                status = "succeeded" if code == 0 else "failed"
        finally:
            # Group kill handles ordinary descendants; systemd additionally kills the entire cgroup.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            selector.close()
            process.stdout.close()
            process.stderr.close()
        if status != "succeeded":
            code = process.returncode
            break
    return (
        status,
        code,
        output[0].decode("utf-8", errors="replace"),
        output[1].decode("utf-8", errors="replace"),
    )


def run(config_file: Path, job_file: Path, work: Path) -> dict:
    for path in [config_file, job_file]:
        protected(path)
    config, job = json.loads(config_file.read_text()), json.loads(job_file.read_text())
    protected(Path(config["public_key_file"]))
    profile = verify_job(job, config, Path(config["public_key_file"]).read_text())
    identity = capture_identity(profile)
    started = time.time()
    result = {
        "status": "failed",
        "identity": identity,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "started_at": started,
    }
    try:
        identity = validate_identity(identity, profile)
        result["identity"] = identity
        if profile["account"] != job["snapshot"]["account"]:
            raise ValueError("Approved and provisioned Linux accounts differ")
        status, code, stdout, stderr = run_commands(
            commands(job["snapshot"], catalog_root(config, job)), job["snapshot"]["timeout_seconds"], work
        )
        result.update(status=status, exit_code=code, stdout=stdout, stderr=stderr)
        if job["snapshot"]["action"] == "check":
            result["prerequisites"] = {
                "status": "passed" if status == "succeeded" else "missing_or_failed",
                "details_in_logs": True,
            }
    except Exception as exc:
        result["stderr"] = "Linux execution rejected: " + type(exc).__name__
    result["finished_at"] = time.time()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--job", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("Linux is required")
    print(json.dumps(run(args.config, args.job, args.work)), flush=True)


if __name__ == "__main__":
    main()
