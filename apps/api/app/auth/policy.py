from pathlib import Path

import yaml

from ..errors import fail


def authorize_execution(settings, principal, actor, profile, test, risk, action):
    return authorize_subject_execution(settings, principal.subject, actor, profile, test, risk, action)


def authorize_subject_execution(settings, subject, actor, profile, test, risk, action):
    if settings.approval_mode == "catalog":
        return
    if not settings.policy_file:
        fail("policy_denied", "Real execution requires an explicit scope policy", 403)
    policy = yaml.safe_load(Path(settings.policy_file).read_text())
    grants = policy.get("subjects", {}).get(subject, [])
    allowed = any(
        action in g.get("actions", [])
        and actor.id in g.get("actors", [])
        and profile.id in g.get("profiles", [])
        and test.guid in g.get("tests", [])
        and risk in g.get("risks", [])
        for g in grants
    )
    if not allowed:
        fail("policy_denied", "Caller is not authorized for this actor, profile, test, risk and action", 403)
