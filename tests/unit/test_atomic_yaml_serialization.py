"""Invoke-AtomicRedTeam rejects a present but empty input_arguments mapping."""

import copy

import pytest
import yaml

from apps.api.app.catalog.serialization import definition_yaml


@pytest.mark.parametrize(
    "inputs", [None, {}, {"target": {"description": "Target", "type": "string", "default": ""}}]
)
def test_render_optional_inputs_without_changing_reviewed_definition(inputs):
    definition = {
        "technique": "T1082",
        "technique_name": "System Information Discovery",
        "name": "Hostname fixture",
        "auto_generated_guid": "11111111-1111-4111-8111-111111111111",
        "executor": {"name": "command_prompt", "command": "hostname\n"},
    }
    if inputs is not None:
        definition["input_arguments"] = inputs
    before = copy.deepcopy(definition)
    rendered = yaml.safe_load(definition_yaml(definition))
    atomic = rendered["atomic_tests"][0]
    assert definition == before
    assert rendered["attack_technique"] == "T1082"
    assert atomic["executor"] == definition["executor"]
    assert "technique" not in atomic and "technique_name" not in atomic
    if inputs:
        assert atomic["input_arguments"] == inputs
    else:
        assert "input_arguments" not in atomic
