"""Foreground systemd service entry point and explicit profile validation."""

import argparse
import fcntl
import json
import os
import signal
import sys
import threading
from pathlib import Path

from ..service import worker
from .broker import Broker, validate_profiles
from .security import protected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/etc/atomic-control/agent.json"))
    parser.add_argument("--validate-profiles", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise SystemExit("The Linux agent requires root and a running systemd system manager")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise SystemExit("A unified cgroup v2 system is required for verified process cleanup")
    protected(args.config)
    lock_path = Path("/var/lib/atomic-control/agent.lock")
    protected(lock_path.parent)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        raise SystemExit(
            "Another agent/probe is running; stop the service before profile validation"
        ) from None
    try:
        config = json.loads(args.config.read_text())
        if config.get("os") != "linux" or config.get("config_file") != str(args.config):
            raise SystemExit("Configuration platform/path mismatch")
        for field in ["public_key_file", "state_root", "work_root"]:
            protected(Path(config[field]))
        if config.get("catalog_sync_enabled") and config.get("delivery_mode") != "on_demand":
            from .catalog_sync import recover

            config = recover(args.config)
        if config.get("delivery_mode") != "on_demand":
            protected(Path(config["catalog_root"]))
        protected(Path(config["python_path"]).resolve())
        stop = threading.Event()
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, lambda *_: stop.set())
        # Recovery stops uncertain units before any probe or new claim.
        if Path(config["state_root"], "active.json").exists():
            from ..enrollment import load_credential
            from ..job_client import JobClient

            credentials = load_credential(Path(config["credential_file"]))
            client = JobClient(config["api_url"], credentials["credential"])
            try:
                Broker(config, client, stop).recover()
            finally:
                client.close()
        validate_profiles(config, args.config)
        if not args.validate_profiles:
            worker(args.config, stop)
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    main()
