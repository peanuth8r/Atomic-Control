import argparse
import getpass
import platform
from pathlib import Path

from apps.agent.enrollment import enroll

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("api_url")
    p.add_argument("credential_file", type=Path)
    args = p.parse_args()
    actor = enroll(
        args.api_url,
        getpass.getpass("Single-use enrollment token: "),
        platform.node(),
        platform.platform(),
        args.credential_file,
    )
    print("Enrolled actor:", actor)
