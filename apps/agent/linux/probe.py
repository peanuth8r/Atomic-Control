"""Identity-only validation; never runs an Atomic command."""

import argparse
import json
from pathlib import Path

from .identity import capture_identity, validate_identity
from .security import protected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--profile-id", required=True)
    args = parser.parse_args()
    protected(args.config)
    config = json.loads(args.config.read_text())
    profile = next(p for p in config["profiles"] if p["id"] == args.profile_id and p["enabled"])
    print(json.dumps(validate_identity(capture_identity(profile), profile)))


if __name__ == "__main__":
    main()
