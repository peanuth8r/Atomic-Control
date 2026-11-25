import json
import shutil
import subprocess
from uuid import uuid4

import pytest

from apps.agent import windows_catalog as catalog
from apps.api.app.catalog.parser import parse_file
from apps.api.app.services.common import fingerprint


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    path = source / "atomics/T1082/T1082.yaml"
    path.parent.mkdir(parents=True)
    shutil.copyfile("config/custom-test.example.yaml", path)
    for args in [
        ("init", "--quiet", "--template="),
        ("config", "user.name", "Fixture"),
        ("config", "user.email", "fixture@example.test"),
        ("add", "atomics"),
        ("commit", "--quiet", "-m", "Fixture catalog"),
    ]:
        subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    definition = parse_file(path)[0]
    config = {"actor_id": str(uuid4()), "hostname": "WINDOWS-FIXTURE", "revision": revision, "os": "windows"}
    value = {
        "protocol": 1,
        "actor_id": config["actor_id"],
        "hostname": config["hostname"],
        "revision": revision,
        "source": "redcanaryco/atomic-red-team",
        "tests": [
            {
                "guid": definition["auto_generated_guid"],
                "technique": "T1082",
                "sha256": fingerprint(definition),
            }
        ],
    }
    install_root = tmp_path / "installed"
    install_root.mkdir()
    calls = []
    original = catalog.git

    def local_transport(root, *args, **kwargs):
        calls.append(args)
        if args[0] == "fetch":
            # Only replace network transport with an isolated fixture repository.
            subprocess.run(
                ["git", "-C", str(root), "fetch", "--quiet", str(source), args[-1]],
                check=True,
                capture_output=True,
            )
            return ""
        return original(root, *args, **kwargs)

    monkeypatch.setattr(catalog, "git", local_transport)
    monkeypatch.setattr(catalog, "protect_tree", lambda root: None)
    monkeypatch.setattr(catalog, "trust_checkout", lambda root: None)
    return config, value, install_root, calls


def test_fresh_catalog_is_verified_before_publishing_and_reinstall_reuses_it(checkout):
    config, value, root, calls = checkout
    assert catalog.install(config, value, root) == config["revision"]
    target = root / "atomic-red-team"
    catalog.verify_checkout(target, value)
    assert ("remote", "add", "origin", catalog.REMOTE) in calls
    assert len([call for call in calls if call[0] == "fetch"]) == 1
    config["catalog_root"] = str(target)
    config["catalog_manifest_file"] = str(root / "catalog-manifest.json")
    assert catalog.reported_revision(config) == config["revision"]
    # A replacement registration has a new UUID but can reuse verified identical content.
    config["actor_id"] = str(uuid4())
    value["actor_id"] = config["actor_id"]
    assert catalog.install(config, value, root) == config["revision"]
    assert len([call for call in calls if call[0] == "fetch"]) == 1
    assert json.loads((root / "catalog-manifest.json").read_text())["actor_id"] == config["actor_id"]


def test_mismatched_content_never_publishes_a_catalog_or_pin(checkout):
    config, value, root, _ = checkout
    value["tests"][0]["sha256"] = "f" * 64
    with pytest.raises(RuntimeError, match="does not match"):
        catalog.install(config, value, root)
    assert not (root / "atomic-red-team").exists()
    assert not (root / "catalog-manifest.json").exists()


def test_dirty_catalog_is_not_replaced_and_pin_is_withdrawn(checkout):
    config, value, root, _ = checkout
    catalog.install(config, value, root)
    target = root / "atomic-red-team"
    (target / "unexpected.txt").write_text("retain me")
    config.update(catalog_root=str(target), catalog_manifest_file=str(root / "catalog-manifest.json"))
    assert catalog.reported_revision(config) == ""
    with pytest.raises(RuntimeError, match="clean"):
        catalog.install(config, value, root)
    assert (target / "unexpected.txt").read_text() == "retain me"


@pytest.mark.parametrize("field", ["actor_id", "hostname", "revision", "source"])
def test_catalog_binding_changes_are_refused_before_fetch(checkout, field):
    config, value, root, calls = checkout
    value[field] = {
        "actor_id": str(uuid4()),
        "hostname": "OTHER-HOST",
        "revision": "a" * 40,
        "source": "untrusted/repo",
    }[field]
    with pytest.raises(ValueError):
        catalog.install(config, value, root)
    assert not calls and not (root / "atomic-red-team").exists()


def test_reparse_paths_and_wrong_actor_receipts_are_not_reported(checkout):
    config, value, root, _ = checkout
    catalog.install(config, value, root)
    target = root / "atomic-red-team"
    config.update(catalog_root=str(target), catalog_manifest_file=str(root / "catalog-manifest.json"))
    config["actor_id"] = str(uuid4())
    assert catalog.reported_revision(config) == ""
    (target / "unsafe-link").symlink_to(root)
    with pytest.raises(RuntimeError, match="reparse"):
        catalog.verify_checkout(target, value)
