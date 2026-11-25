"""Build shell invocations only from the exact reviewed definition and its defaults."""

import re
from pathlib import Path

SHELLS = {"bash": "/bin/bash", "sh": "/bin/sh"}


def commands(snapshot: dict, catalog_root: Path) -> list[list[str]]:
    definition = snapshot["definition"]
    executor = definition["executor"]
    if "linux" not in definition["supported_platforms"] or executor["name"] not in SHELLS:
        raise ValueError("Linux supports only bash/sh Atomic executors")
    defaults = {k: v.get("default") for k, v in definition.get("input_arguments", {}).items()}
    if defaults != snapshot["input_values"]:
        raise ValueError("Input overrides are not permitted")
    values = {**defaults, "PathToAtomicsFolder": str(catalog_root / "atomics")}

    def command(text, shell):
        if shell not in SHELLS or not isinstance(text, str) or not text.strip():
            raise ValueError("Unsupported or empty shell command")

        def replace(match):
            key = match.group(1)
            value = values.get(key)
            if key not in values or isinstance(value, (dict, list, bool)) or value is None:
                raise ValueError("Missing or unsupported Atomic default input")
            return str(value)

        expanded = re.sub(r"#\{([^{}]+)\}", replace, text)
        if "#{" in expanded or "\0" in expanded or len(expanded.encode()) > 100_000:
            raise ValueError("Unresolved or oversized Atomic command")
        # No shell login files, CLI overrides or fetched prerequisites.
        return [SHELLS[shell], *(["--noprofile", "--norc"] if shell == "bash" else []), "-c", expanded]

    action = snapshot["action"]
    if action == "check":
        shell = definition.get("dependency_executor_name", executor["name"])
        return [command(dep.get("prereq_command"), shell) for dep in definition.get("dependencies", [])]
    if action not in {"execute", "cleanup"}:
        raise ValueError("Unsupported Atomic action")
    key = "command" if action == "execute" else "cleanup_command"
    return [command(executor.get(key), executor["name"])]
