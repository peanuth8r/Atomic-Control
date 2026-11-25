"""Clock allowance for control-plane-issued agent tokens, without extending expiry."""

import time

ISSUED_AT_BACKDATE_SECONDS = 5


def token_issued_at(now: float | None = None) -> int:
    # Agents validate iat immediately on receipt. A sub-second negative clock
    # offset can otherwise reject a freshly issued grant before it is journaled.
    # Backdate issuance only: callers retain their original exp/lease deadlines,
    # and agent signature, audience, issuer and time checks remain enabled.
    return int(time.time() if now is None else now) - ISSUED_AT_BACKDATE_SECONDS
