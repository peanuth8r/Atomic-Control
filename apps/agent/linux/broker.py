"""Root systemd broker: one signed attempt, durable journal, cgroup-wide stop, no replay."""

import json
import os
import subprocess
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID, uuid4

from ..execution_broker import verify_job
from ..job_client import heartbeat_payload
from .identity import validate_identity
from .security import protected, write_json

SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"


def unit_name(attempt_id: str) -> str:
    return "atomic-control-job-" + str(UUID(attempt_id)) + ".service"


def profile_command(
    config: dict, profile: dict, unit: str, timeout: int, arguments: list[str], work: Path
) -> list[str]:
    import pwd

    account = pwd.getpwnam(profile["account"])
    if profile["expected_sid"] != f"uid:{account.pw_uid}":
        raise ValueError("Provisioned account UID changed")
    root = profile["privilege"] == "elevated"
    if (account.pw_uid == 0) != root or (account.pw_gid == 0) != root:
        raise ValueError("Provisioned account privilege changed")
    properties = [
        "Type=exec",
        f"User={account.pw_uid}",
        f"Group={account.pw_gid}",
        "KillMode=control-group",
        "SendSIGKILL=yes",
        "TimeoutStopSec=5s",
        f"RuntimeMaxSec={timeout}s",
        "UMask=0077",
        "StandardInput=null",
        "LimitCORE=0",
        "TasksMax=256",
        "InaccessiblePaths=/var/lib/atomic-control/secrets",
        "ReadOnlyPaths=/opt/atomic-control /etc/atomic-control /var/lib/atomic-control/jobs",
        f"WorkingDirectory={work}",
    ]
    if not root:
        properties += ["NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities="]
    return [
        SYSTEMD_RUN,
        "--quiet",
        "--wait",
        "--pipe",
        "--unit=" + unit,
        *("--property=" + p for p in properties),
        config["python_path"],
        "-I",
        *arguments,
    ]


def verify_cgroup_empty(control_group: str, root: Path = Path("/sys/fs/cgroup")):
    group = PurePosixPath(control_group)
    if not group.is_absolute() or ".." in group.parts or control_group == "/":
        raise RuntimeError("Invalid execution cgroup path")
    path = root / str(group).lstrip("/")
    if not path.exists():
        return  # systemd removed an empty cgroup.

    def fail_walk(error):
        raise error

    for folder, _, _ in os.walk(path, onerror=fail_walk):
        processes = Path(folder) / "cgroup.procs"
        try:
            if processes.read_text().strip():
                raise RuntimeError("Execution cgroup still contains processes; reconciliation required")
        except FileNotFoundError:
            if Path(folder).exists():
                raise RuntimeError("Cannot inspect execution cgroup processes") from None


def stop_unit(unit: str):
    if not unit.startswith(("atomic-control-job-", "atomic-control-probe-")):
        raise ValueError("Invalid agent unit")
    # Transient units may already have been garbage-collected after --wait completes.
    state = subprocess.run(
        [
            SYSTEMCTL,
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=ControlGroup",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    control_group = next(
        (line.partition("=")[2] for line in state.stdout.splitlines() if line.startswith("ControlGroup=")), ""
    )
    if "ActiveState=active" in state.stdout and not control_group:
        raise RuntimeError("Cannot identify the active execution cgroup")
    if "LoadState=not-found" not in state.stdout:
        subprocess.run([SYSTEMCTL, "stop", unit], capture_output=True, check=True, timeout=15)
        state = subprocess.run(
            [SYSTEMCTL, "show", unit, "--property=ActiveState"], capture_output=True, text=True, timeout=10
        )
    if not any(line in {"ActiveState=inactive", "ActiveState=failed"} for line in state.stdout.splitlines()):
        raise RuntimeError("Cannot establish that the execution unit stopped")
    if control_group:
        verify_cgroup_empty(control_group)


def validate_profiles(config: dict, config_file: Path):
    work = Path(config["work_root"])
    protected(work)
    results: dict[str, Any] = {}
    for profile in config["profiles"]:
        profile["validated"] = False
        results[profile["id"]] = {"healthy": False, "identity": None, "error": "disabled"}
        if not profile.get("enabled", False):
            continue
        unit = "atomic-control-probe-" + str(uuid4()) + ".service"
        try:
            command = profile_command(
                config,
                profile,
                unit,
                15,
                ["-m", "apps.agent.linux.probe", "--config", str(config_file), "--profile-id", profile["id"]],
                work,
            )
            response = subprocess.run(command, capture_output=True, text=True, timeout=25, check=True)
            evidence = json.loads(response.stdout)
            if (
                evidence["expected_profile_id"] != profile["id"]
                or evidence["expected_account_sid"] != profile["expected_sid"]
            ):
                raise ValueError("Profile probe identity binding differs")
            evidence = validate_identity(evidence, profile)
            profile["validated"] = True
            results[profile["id"]] = {"healthy": True, "identity": evidence, "error": ""}
        except KeyError:
            results[profile["id"]] = {"healthy": False, "identity": None, "error": "account_missing"}
        except ValueError:
            results[profile["id"]] = {"healthy": False, "identity": None, "error": "identity_mismatch"}
        except (OSError, subprocess.SubprocessError):
            results[profile["id"]] = {"healthy": False, "identity": None, "error": "probe_failed"}
        finally:
            stop_unit(unit)
    config["profile_validation_results"] = results
    write_json(config_file, config, 0o644)
    return results


class Broker:
    def __init__(self, config: dict, client, stop: threading.Event | None = None):
        self.config, self.client = config, client
        self.stop = stop or threading.Event()
        self.root = Path(config["state_root"])
        protected(self.root)
        self.journal = self.root / "active.json"
        protected(Path(config["public_key_file"]))
        self.public_key = Path(config["public_key_file"]).read_text()

    def recover(self):
        from ..artifact_execution import check_orphans

        check_orphans(self)
        if self.journal.exists() or self.journal.is_symlink():
            protected(self.journal, private=True)
            from ..artifact_execution import recover

            if recover(self):
                return
            job = json.loads(self.journal.read_text())
            stop_unit(unit_name(job["attempt_id"]))
            raise RuntimeError("Uncertain prior Linux job. Reconcile before clearing the local journal")

    def execute(self, job):
        if job["snapshot"].get("artifact"):
            from ..artifact_execution import execute

            return execute(self, job, self._execute)
        return self._execute(job)

    def _execute(self, job):
        catalog_journal = self.root.parent / "catalog-install.json"
        if catalog_journal.exists() or catalog_journal.is_symlink():
            raise RuntimeError("Catalog installation requires recovery before execution")
        profile = verify_job(job, self.config, self.public_key)
        if not job.get("delivery_state"):
            if self.journal.exists() or self.journal.is_symlink():
                raise RuntimeError("Unreconciled job prevents execution")
            # Persist/fsync before any dispatch. A lost acknowledgement is never replayed.
            write_json(self.journal, job, exclusive=True)
        folder = self.root / str(UUID(job["attempt_id"]))
        folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        job_file = folder / "job.json"
        write_json(job_file, job, 0o644)
        work = Path(self.config["work_root"]) / str(UUID(job["attempt_id"]))
        work.mkdir(mode=0o700)
        import pwd

        account = pwd.getpwnam(profile["account"])
        os.chown(work, account.pw_uid, account.pw_gid)
        proof = {"attempt_id": job["attempt_id"], "fence": job["fence"]}
        response = self.client.post(f"agents/jobs/{job['run_id']}/heartbeat", proof)
        if response["cancel_requested"] or response["lease_expires_at"] <= time.time():
            raise RuntimeError("Job cancelled or lease expired before dispatch")
        unit = unit_name(job["attempt_id"])
        command = profile_command(
            self.config,
            profile,
            unit,
            job["snapshot"]["timeout_seconds"] + 10,
            [
                "-m",
                "apps.agent.linux.runner",
                "--config",
                self.config["config_file"],
                "--job",
                str(job_file),
                "--work",
                str(work),
            ],
            work,
        )
        out_path, err_path = folder / "stdout.json", folder / "stderr.log"
        with (
            open(out_path, "xb", opener=lambda path, flags: os.open(path, flags, 0o600)) as out,
            open(err_path, "xb", opener=lambda path, flags: os.open(path, flags, 0o600)) as err,
        ):
            process = subprocess.Popen(command, stdout=out, stderr=err, stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + job["snapshot"]["timeout_seconds"] + 25
            renewal = time.monotonic()
            last_health = 0.0
            try:
                while process.poll() is None:
                    if self.stop.is_set() or time.monotonic() > deadline:
                        raise RuntimeError("Execution interrupted; reconcile the Linux host")
                    if out_path.stat().st_size > 600_000 or err_path.stat().st_size > 65536:
                        raise RuntimeError("Oversized Linux execution evidence")
                    if time.monotonic() - renewal >= 5:
                        response = self.client.post(f"agents/jobs/{job['run_id']}/heartbeat", proof)
                        if response["cancel_requested"] or response["lease_expires_at"] <= time.time():
                            raise RuntimeError("Execution cancelled or lease lost")
                        renewal = time.monotonic()
                    if time.time() - last_health >= self.config.get("heartbeat_seconds", 30):
                        self.client.post("agents/heartbeat", heartbeat_payload(self.config, job["run_id"]))
                        last_health = time.time()
                    self.stop.wait(0.1)
            finally:
                try:
                    stop_unit(unit)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
        if process.returncode or out_path.stat().st_size > 600_000:
            raise RuntimeError("Linux execution returned no conclusive evidence")
        result = json.loads(out_path.read_text())
        result.update(**proof, simulated=False)
        if not job.get("delivery_state"):
            self.client.post(f"agents/jobs/{job['run_id']}/result", result)
            self.journal.unlink()
        return result
