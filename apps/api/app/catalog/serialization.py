"""Render normalized catalog definitions for Invoke-AtomicRedTeam."""

import yaml


def definition_yaml(definition, *, legacy=False):
    atomic = {k: v for k, v in definition.items() if k not in {"technique", "technique_name"}}
    # Catalog normalization supplies {}, but upstream requires this optional field
    # to be absent when there are no inputs. Keep the reviewed definition intact.
    if not legacy and atomic.get("input_arguments") == {}:
        atomic.pop("input_arguments", None)
    return yaml.safe_dump(
        {
            "attack_technique": definition["technique"],
            "display_name": definition["technique_name"],
            "atomic_tests": [atomic],
        },
        sort_keys=False,
        allow_unicode=True,
    ).encode()
