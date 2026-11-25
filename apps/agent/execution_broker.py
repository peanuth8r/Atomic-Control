import json
import os
import subprocess
import threading
import time
from pathlib import Path
from uuid import UUID

import jwt

from apps.api.app.services.common import fingerprint

from .catalog_validation import validate_catalog
from .job_client import heartbeat_payload


def verify_job(job: dict, config: dict, public_key: str, require_payload=True):
    claims = jwt.decode(
        job["grant"],
        public_key,
        algorithms=["RS256"],
        audience=config["actor_id"],
        issuer="atomic-control",
        options={"require": ["exp", "iat", "aud", "iss"]},
    )
    for field in ["run_id", "attempt_id", "fence", "snapshot", "snapshot_hash", "lease_expires_at"]:
        if claims.get(field) != job.get(field):
            raise ValueError("Signed job and assignment differ")
    s = claims["snapshot"]
    if fingerprint(s) != claims["snapshot_hash"] or s["simulated"] or s["actor_id"] != config["actor_id"]:
        raise ValueError("Job authorization mismatch")
    profile = next(
        (p for p in config["profiles"] if p["id"] == s["execution_profile_id"] and p.get("enabled", False)),
        None,
    )
    if (
        not profile
        or not profile.get("validated", False)
        or any(profile[k] != s[k] for k in ["expected_sid", "privilege", "profile_key"])
    ):
        raise ValueError("Unknown or mismatched provisioned execution identity")
    for field in ["run_id", "attempt_id"]:
        UUID(job[field])
    if s["action"] not in {"execute", "check", "cleanup"} or not 10 <= s["timeout_seconds"] <= 600:
        raise ValueError("Invalid operation constraints")
    if s.get("actor_os", "windows") != config.get("os", "windows"):
        raise ValueError("Job platform differs from configured actor")
    from apps.api.app.catalog.parser import execution_platforms

    if config.get("os", "windows") not in execution_platforms(s["definition"]):
        raise ValueError("Unsupported platform or executor")
    if s.get("artifact"):
        from .artifacts import payload_root, verify_descriptor, verify_payload

        if config.get("delivery_mode") != "on_demand":
            raise ValueError("Agent is not configured for on-demand delivery")
        purpose = "artifact-execute-v1" if require_payload else "artifact-prepare-v1"
        if claims.get("purpose") != purpose:
            raise ValueError("Artifact grant has the wrong purpose")
        verify_descriptor(s["artifact"], s, public_key)
        if require_payload:
            if config.get("os") == "linux":
                from .linux.security import protected_tree

                protected_tree(payload_root(config, job))
            verify_payload(payload_root(config, job), s, public_key)
        return profile
    if config.get("delivery_mode") == "on_demand":
        raise ValueError("On-demand agent requires a signed artifact")
    if config.get("os") == "linux":
        from .linux.security import protected_tree

        protected_tree(Path(config["catalog_root"]))
    validate_catalog(Path(config["catalog_root"]), s, config["revision"], config.get("os") == "linux")
    return profile


def restrict_acl(path: Path, sid: str | None = None, writable: bool = False):
    if os.name != "nt":
        raise RuntimeError("ACL enforcement requires Windows")
    grants = (
        ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]
        if path.is_dir()
        else ["*S-1-5-18:F", "*S-1-5-32-544:F"]
    )
    if sid:
        grants.append(
            "*" + sid + (":(OI)(CI)M" if writable else ":(OI)(CI)RX")
            if path.is_dir()
            else "*" + sid + (":M" if writable else ":RX")
        )
    subprocess.run(
        ["icacls.exe", str(path), "/inheritance:r", "/grant:r", *grants], check=True, capture_output=True
    )


class Broker:
    def __init__(self, config: dict, client, stop: threading.Event | None = None):
        self.config, self.client = config, client
        self.stop = stop or threading.Event()
        self.root = Path(config["state_root"])
        self.root.mkdir(parents=True, exist_ok=True)
        self.journal = self.root / "active.json"
        self.public_key = Path(config["public_key_file"]).read_text()
        self.containment = None

    def recover(self):
        from .artifact_execution import check_orphans

        check_orphans(self)
        if not self.journal.exists():
            return
        from .artifact_execution import recover

        if recover(self):
            return
        job = json.loads(self.journal.read_text())
        # Never relaunch. Stop the preprovisioned task; backend lease will become inconclusive.
        profile = next(
            p for p in self.config["profiles"] if p["id"] == job["snapshot"]["execution_profile_id"]
        )
        self.stop_task(profile)
        raise RuntimeError("Uncertain prior job. Administrator reconciliation and journal clearance required")

    def stop_task(self, profile):
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()

        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        task = scheduler.GetFolder("\\AtomicControl").GetTask(profile["id"])
        if task.State == 4:
            task.Stop(0)
        deadline = time.monotonic() + 15
        while task.State == 4:
            if time.monotonic() >= deadline:
                raise RuntimeError("Cannot establish that the execution task stopped")
            time.sleep(0.1)

    def execute(self, job):
        if job["snapshot"].get("artifact"):
            from .artifact_execution import execute

            return execute(self, job, self._execute)
        return self._execute(job)

    def _execute(self, job):
        if os.name != "nt":
            raise RuntimeError("Real broker requires Windows")
        profile = verify_job(job, self.config, self.public_key)
        if not job.get("delivery_state"):
            if self.journal.exists():
                raise RuntimeError("Unreconciled job prevents execution")
            with self.journal.open("x") as handle:
                json.dump(job, handle)
            restrict_acl(self.journal)
        # Provisioning creates this profile's fixed read-only input and separate writable output directory.
        folder = self.root / profile["id"]
        input_file, lease_file = folder / "job.json", folder / "lease.json"
        output_file = folder / "output" / "result.json"
        if output_file.exists():
            output_file.unlink()
        input_file.write_text(json.dumps(job))
        restrict_acl(input_file, profile["expected_sid"])
        deadline = time.monotonic() + job["snapshot"]["timeout_seconds"] + 15
        stopped = threading.Event()
        failure: list[str] = []

        def renewal():
            last_health = 0.0
            while not stopped.is_set():
                try:
                    if time.time() - last_health >= self.config.get("heartbeat_seconds", 30):
                        self.client.post("agents/heartbeat", heartbeat_payload(self.config, job["run_id"]))
                        last_health = time.time()
                    response = self.client.post(
                        f"agents/jobs/{job['run_id']}/heartbeat",
                        {"attempt_id": job["attempt_id"], "fence": job["fence"]},
                    )
                    lease_file.write_text(
                        json.dumps(
                            {"expires_at": response["lease_expires_at"], "attempt_id": job["attempt_id"]}
                        )
                    )
                    restrict_acl(lease_file, profile["expected_sid"])
                    if response["cancel_requested"]:
                        failure.append("cancelled")
                        self.stop_task(profile)
                        return
                except Exception:
                    failure.append("inconclusive")
                    self.stop_task(profile)
                    return
                if stopped.wait(10):
                    return

        # Establish the lease and cancellation signal before dispatch.
        response = self.client.post(
            f"agents/jobs/{job['run_id']}/heartbeat", {"attempt_id": job["attempt_id"], "fence": job["fence"]}
        )
        if response["cancel_requested"]:
            raise RuntimeError("Job was cancelled before dispatch")
        lease_file.write_text(
            json.dumps({"expires_at": response["lease_expires_at"], "attempt_id": job["attempt_id"]})
        )
        restrict_acl(lease_file, profile["expected_sid"])
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()

        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        task = scheduler.GetFolder("\\AtomicControl").GetTask(profile["id"])
        if job["snapshot"].get("artifact"):
            from .windows_processes import create

            self.containment = create(job["attempt_id"], profile["expected_sid"])
        task.Run(None)
        worker = threading.Thread(target=renewal, daemon=True)
        worker.start()
        try:
            while not output_file.exists() and not failure:
                if self.stop.is_set():
                    self.stop_task(profile)
                    failure.append("inconclusive")
                    break
                if time.monotonic() >= deadline:
                    failure.append("timed_out")
                    self.stop_task(profile)
                    break
                time.sleep(0.25)
            if failure:
                raise RuntimeError("Job stopped: " + failure[0] + "; reconcile before further execution")
            if output_file.stat().st_size > 200_000:
                raise RuntimeError("Oversized broker result")
            result = json.loads(output_file.read_text())
            result.update(attempt_id=job["attempt_id"], fence=job["fence"], simulated=False)
            if not job.get("delivery_state"):
                self.client.post(f"agents/jobs/{job['run_id']}/result", result)
                self.journal.unlink()
            return result
        finally:
            stopped.set()
            worker.join(timeout=25)
