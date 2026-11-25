"""Run the separate real-mode HTTPS API/dashboard and MCP service; Ctrl-C stops only these children."""

import os
import signal
import socket
import subprocess
import sys
import time

from dotenv import dotenv_values

from .setup import ROOT, RUNTIME


def environment():
    path = RUNTIME / "application.env"
    if path.stat().st_mode & 0o077:
        raise ValueError("The deployment environment must be private")
    values = dotenv_values(path, interpolate=False)
    return {**os.environ, **{key: value for key, value in values.items() if value is not None}}


def main():
    if not (ROOT / "apps/frontend/dist/index.html").is_file():
        raise SystemExit("Build the frontend before starting the real local deployment")
    env = environment()
    for host, port in [(env.get("ATOMIC_BIND_ADDRESS", "127.0.0.1"), 19443), ("127.0.0.1", 19444)]:
        with socket.socket() as sock:
            if sock.connect_ex((host, port)) == 0:
                raise SystemExit(f"Port {port} is already in use; the existing process will not be replaced")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, check=True)
    children: list[subprocess.Popen] = []

    def stop(*_):
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for service in ["control", "mcp"]:
            children.append(
                subprocess.Popen(
                    [sys.executable, "-m", "apps.local_identity.serve", service, "--runtime", str(RUNTIME)],
                    cwd=ROOT,
                    env=env,
                )
            )
        print("Real dashboard:", env["ATOMIC_PUBLIC_URL"], flush=True)
        print("Authenticated MCP (loopback):", env["ATOMIC_MCP_RESOURCE"], flush=True)
        print("No execution agent or Atomic command is started.", flush=True)
        while all(child.poll() is None for child in children):
            time.sleep(0.5)
    finally:
        stop()


if __name__ == "__main__":
    main()
