"""Execute portable PowerShell setup logic with enrollment/native actions mocked."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PWSH = shutil.which("pwsh") or "/tmp/atomic-powershell-parser/pwsh"


@pytest.mark.skipif(
    not Path(PWSH).is_file(), reason="PowerShell is required for installer orchestration checks"
)
@pytest.mark.parametrize(
    "case",
    [
        "tree-reuse",
        "tree-change",
        "tree-missing",
        "tree-extra",
        "tree-link",
        "tree-metadata",
        "tree-install",
        "tree-publish-failure",
        "yaml-install",
        "yaml-reuse",
        "yaml-change",
        "yaml-bad-hash",
        "installer-success",
        "installer-legacy",
        "installer-failure",
    ],
)
def test_windows_installation_flow(tmp_path, case):
    result = subprocess.run(
        [
            PWSH,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ROOT / "tests/powershell/windows_installation.ps1"),
            "-Root",
            str(ROOT),
            "-Work",
            str(tmp_path / case),
            "-Case",
            case,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"Passed {case}" in result.stdout
