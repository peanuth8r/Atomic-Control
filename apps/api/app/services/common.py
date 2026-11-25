import hashlib
import json
import re
import time
from typing import Any

from ..models import Audit, Cleanup, Event, Run, RunBatch


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def fingerprint(value: Any) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")))


def audit(db, identity: str, action: str, resource: str, **details):
    db.add(Audit(identity=identity, action=action, resource=resource, details=details))


def transition(db, run: Run, state: str, identity: str):
    run.status = state
    run.updated_at = time.time()
    db.add(Event(run_id=run.id, status=state, identity=identity))
    cleanup = db.get(Cleanup, run.id)
    if cleanup:
        cleanup.status = state
    audit(db, identity, "run." + state, run.id)
    identity_failed = run.result is not None and not run.result.get("identity_verified", False)
    if run.batch_id and (
        state in {"preparation_failed", "failed", "timed_out", "rejected", "inconclusive"} or identity_failed
    ):
        batch = db.get(RunBatch, run.batch_id)
        if (
            batch
            and not batch.cancelled
            and run.queue_position > batch.acknowledged_position
            and (batch.failure_policy == "pause" or state in {"rejected", "inconclusive"} or identity_failed)
        ):
            from .run_batches import pause

            pause(db, batch, "identity_verification_failed" if identity_failed else state, run.id, identity)


def redact(text: str, limit: int) -> tuple[str, bool]:
    # Bounded ingestion; Atomic output can contain secrets. Do not retain common credential patterns.
    text = re.sub(
        r"(?i)(password|authorization|access_token|secret|credential)\s*[:=]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]", text)
    return text[:limit], len(text) > limit
