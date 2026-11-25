"""Bounded, non-executing validation for untrusted Atomic YAML documents."""

import json
import re
from typing import Any
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from yaml.events import AliasEvent

MAX_FILE_BYTES = 1_000_000
TECHNIQUE = r"T\d{4}(?:\.\d{3})?"


class CatalogValidationError(ValueError):
    pass


class UniqueSafeLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise CatalogValidationError("Mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


class Executor(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    name: str = Field(min_length=1, max_length=64)
    command: str = Field(default="", max_length=MAX_FILE_BYTES)
    cleanup_command: str | None = Field(default=None, max_length=MAX_FILE_BYTES)
    steps: str | None = None
    elevation_required: bool = False


class Atomic(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    auto_generated_guid: str
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=MAX_FILE_BYTES)
    supported_platforms: list[str] = Field(min_length=1, max_length=50)
    executor: Executor
    dependencies: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    input_arguments: dict[str, dict[str, Any]] = Field(default_factory=dict, max_length=100)


class Document(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    attack_technique: str = Field(pattern="^" + TECHNIQUE + "$")
    display_name: str = Field(min_length=1, max_length=256)
    atomic_tests: list[Atomic] = Field(min_length=1, max_length=1000)


def parse_yaml(content: str) -> list[dict]:
    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        raise CatalogValidationError("YAML file exceeds the 1 MB limit")
    try:
        for index, event in enumerate(yaml.parse(content)):
            if index > 100_000 or isinstance(event, AliasEvent) or getattr(event, "anchor", None):
                raise CatalogValidationError("YAML anchors, aliases and excessive nesting are unsupported")
        source = yaml.load(content, Loader=UniqueSafeLoader)
        Document.model_validate(source)
        # Reject dates, sets, non-finite numbers and non-JSON extensions before persistence.
        json.dumps(source, allow_nan=False)
        results = []
        seen = set()
        for atomic in source["atomic_tests"]:
            guid = str(UUID(atomic["auto_generated_guid"]))
            if guid in seen:
                raise CatalogValidationError("Duplicate Atomic GUID in document")
            seen.add(guid)
            if atomic["executor"]["name"] != "manual" and not atomic["executor"].get("command", "").strip():
                raise CatalogValidationError("Non-manual executors require a command")
            result = {
                **atomic,
                "technique": source["attack_technique"],
                "technique_name": source["display_name"],
                "auto_generated_guid": guid,
                "input_arguments": atomic.get("input_arguments", {}),
            }
            results.append(result)
        return results
    except ValidationError as exc:
        fields = ", ".join(".".join(str(v) for v in e["loc"]) for e in exc.errors()[:8])
        raise CatalogValidationError("Invalid Atomic schema at: " + fields) from None
    except (yaml.YAMLError, TypeError, RecursionError, ValueError) as exc:
        if isinstance(exc, CatalogValidationError):
            raise
        raise CatalogValidationError("Invalid YAML, GUID, or unsupported value type") from None


def pinned(revision: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{40}", revision))
