import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .enrollment import load_credential, save_credential
from .execution_broker import Broker
from .job_client import JobClient, heartbeat_payload
from .logging import error_fields, event


def worker(config_file: Path, stop: threading.Event):
    config = json.loads(config_file.read_text())
    credentials_file = Path(config["credential_file"])
    credentials = load_credential(credentials_file)
    if credentials["actor_id"] != config["actor_id"]:
        raise RuntimeError("Enrolled and configured actor identities differ")
    client = JobClient(config["api_url"], credentials["credential"])
    broker_class: Any = Broker
    if config.get("os") == "linux":
        from .linux.broker import Broker as LinuxBroker

        broker_class = LinuxBroker
    broker = broker_class(config, client, stop)
    last_heartbeat = 0.0
    try:
        while not stop.is_set():
            stage = "recover"
            try:
                broker.recover()
                if config.get("profile_sync_enabled") or (
                    config.get("os") == "linux" and config.get("catalog_sync_enabled")
                ):
                    config = json.loads(config_file.read_text())
                    broker.config = config
                if (
                    config.get("os") == "linux"
                    and config.get("catalog_sync_enabled")
                    and config.get("delivery_mode") != "on_demand"
                ):
                    from .linux.catalog_sync import recover

                    config = recover(config_file)
                    broker.config = config
                if credentials["expires_at"] - time.time() < 3600:
                    stage = "rotate_credentials"
                    replacement = client.post("agents/credentials/rotate")
                    credentials.update(replacement)
                    save_credential(credentials_file, credentials)
                    client.close()
                    client = JobClient(config["api_url"], credentials["credential"])
                    broker.client = client
                if time.time() - last_heartbeat >= config.get("heartbeat_seconds", 30):
                    stage = "actor_heartbeat"
                    client.post("agents/heartbeat", heartbeat_payload(config))
                    last_heartbeat = time.time()
                if config.get("profile_sync_enabled"):
                    stage = "synchronize_profiles"
                    if config.get("os") == "linux":
                        from .linux.profile_sync import synchronize
                    else:
                        from .windows_profile_sync import synchronize

                    config = synchronize(config, config_file, client)
                    broker.config = config
                if (
                    config.get("os") == "linux"
                    and config.get("catalog_sync_enabled")
                    and config.get("delivery_mode") != "on_demand"
                ):
                    stage = "synchronize_catalog"
                    from .linux.catalog_sync import synchronize as synchronize_catalog

                    config = synchronize_catalog(config, config_file, client)
                    broker.config = config
                stage = "claim_job"
                job = client.post("agents/jobs/claim")["job"]
                if job:
                    stage = "record_claim"
                    event("job.claimed", run_id=job["run_id"])
                    stage = "execute_job"
                    broker.execute(job)
                    event("job.reported", run_id=job["run_id"])
            except Exception as error:
                event("worker.error", stage=stage, **error_fields(error))
                if broker.journal.exists() and json.loads(broker.journal.read_text()).get("delivery_state"):
                    # Recovery retries only evidence/removal; it never launches the test again.
                    stop.wait(config.get("poll_seconds", 5))
                    continue
                if broker.journal.exists():
                    # Fail closed. Keep the server lease and local journal for reconciliation.
                    raise RuntimeError("Execution outcome requires administrator reconciliation") from None
                if (
                    config.get("os") == "linux"
                    and config.get("catalog_sync_enabled")
                    and config.get("delivery_mode") != "on_demand"
                ):
                    from .linux.catalog_sync import journal_path

                    if journal_path(config).exists() or journal_path(config).is_symlink():
                        raise RuntimeError(
                            "Catalog installation requires recovery before claiming work"
                        ) from None
            stop.wait(config.get("poll_seconds", 5))
    finally:
        client.close()


if os.name == "nt":
    import win32service
    import win32serviceutil

    class AtomicControlAgent(win32serviceutil.ServiceFramework):
        _svc_name_ = "AtomicControlAgent"
        _svc_display_name_ = "Atomic Control Agent"
        _svc_description_ = "Outbound, approved Atomic validation job agent"

        def __init__(self, args):
            super().__init__(args)
            self.stop = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop.set()

        def SvcDoRun(self):
            config = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "AtomicControl" / "agent.json"
            worker(config, self.stop)


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit(
            "Use the Linux systemd agent entry point on Linux; this entry point requires Windows."
        )
    win32serviceutil.HandleCommandLine(
        AtomicControlAgent, serviceClassString="apps.agent.service.AtomicControlAgent"
    )
