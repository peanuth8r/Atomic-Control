"""Provisioning-time token-only probe. Does not import or run any Atomic test."""

import argparse
import json
from pathlib import Path
from uuid import UUID

from .identity_validation import capture_identity, validate_identity

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--profile-id", required=True)
    args = parser.parse_args()
    profile_id = str(UUID(args.profile_id))
    config = json.loads(args.config.read_text())
    profile = next(p for p in config["profiles"] if p["id"] == profile_id)
    identity = validate_identity(capture_identity(profile_id, profile["expected_sid"]), profile)
    output = Path(config["state_root"]) / profile_id / "output" / "identity-probe.json"
    output.write_text(json.dumps(identity, indent=2))
