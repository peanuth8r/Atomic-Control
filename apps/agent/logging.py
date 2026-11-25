import json
import sys
from datetime import UTC, datetime


def event(name: str, **fields):
    # Call sites pass IDs and states, never transport secrets or raw exceptions.
    message = json.dumps({"timestamp": datetime.now(UTC).isoformat(), "event": name, **fields})
    try:
        print(message, flush=True)
    except (OSError, ValueError, AttributeError):
        pass  # A Windows service may have no usable console. Logging cannot stop a job.
    if sys.platform == "win32":
        try:
            import servicemanager

            sink = servicemanager.LogErrorMsg if name.endswith("error") else servicemanager.LogInfoMsg
            sink(message)
        except Exception:
            pass  # Event Log availability must not change execution/recovery behavior.


def error_fields(error):
    """Bounded diagnostics; exception text and HTTP request headers can hold secrets."""
    fields: dict[str, str | int] = {"error_type": type(error).__name__}
    for key in ("winerror", "errno", "returncode"):
        value = getattr(error, key, None)
        if isinstance(value, int):
            fields[key] = value
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        fields["http_status"] = status
    reasons = {
        "Signed job and assignment differ": "assignment_binding_mismatch",
        "Job authorization mismatch": "snapshot_binding_mismatch",
        "Unknown or mismatched provisioned execution identity": "profile_binding_mismatch",
        "Invalid operation constraints": "invalid_operation_constraints",
        "Job platform differs from configured actor": "platform_mismatch",
        "Unsupported platform or executor": "unsupported_executor",
        "Agent is not configured for on-demand delivery": "delivery_mode_mismatch",
        "Artifact grant has the wrong purpose": "grant_purpose_mismatch",
        "On-demand agent requires a signed artifact": "artifact_missing",
        "Artifact signature mismatch": "artifact_signature_mismatch",
        "Artifact manifest hash mismatch": "artifact_manifest_hash_mismatch",
        "Artifact differs from approved snapshot": "artifact_snapshot_mismatch",
    }
    if isinstance(error, ValueError) and (reason := reasons.get(str(error))):
        fields["reason"] = reason
    return fields
