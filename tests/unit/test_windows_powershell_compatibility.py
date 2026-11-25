"""Run the fixed wrapper with fixture modules, never Atomic commands."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PWSH = shutil.which("pwsh") or "/tmp/atomic-powershell-parser/pwsh"


@pytest.mark.skipif(not Path(PWSH).is_file(), reason="PowerShell is required")
@pytest.mark.parametrize("case", ["desktop", "core", "hash", "strict"])
def test_wrapper_platform_compatibility(tmp_path, case):
    result = subprocess.run(
        [
            PWSH,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ROOT / "tests/powershell/windows_platform_compatibility.ps1"),
            "-Root",
            str(ROOT),
            "-Work",
            str(tmp_path),
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
