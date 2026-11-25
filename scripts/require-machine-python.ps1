# Shared preflight for elevated Windows installation and task provisioning.
function Assert-AtomicMachinePython {
    param([Parameter(Mandatory)][string]$PythonPath)
    if (-not [IO.Path]::IsPathRooted($PythonPath) -or -not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        throw 'Provide an existing absolute path to the all-users python.exe executable.'
    }
    if ([IO.Path]::GetExtension($PythonPath) -ne '.exe') { throw 'Select python.exe, not an alias or a misspelled executable.' }
    $raw = & $PythonPath -I -c 'import json,sys,sysconfig; print(json.dumps(dict(major=sys.version_info.major,minor=sys.version_info.minor,is_global=sys.prefix==sys.base_prefix,paths=sysconfig.get_paths(),executable=sys.executable,prefix=sys.prefix)))'
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the selected Python executable.' }
    $info = $raw | ConvertFrom-Json
    if ($info.major -ne 3 -or $info.minor -lt 12 -or -not $info.is_global) {
        throw 'Use an all-users Python 3.12+ installation, not a user virtual environment.'
    }
    $roots = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, ([IO.Path]::Combine($env:SystemDrive + '\', 'Users')))
    $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name ProfilesDirectory -ErrorAction SilentlyContinue
    if ($profiles) { $roots += [Environment]::ExpandEnvironmentVariables($profiles.ProfilesDirectory) }
    foreach ($candidate in @($PythonPath, $info.executable, $info.prefix)) {
        $full = [IO.Path]::GetFullPath($candidate).TrimEnd('\')
        if ($full -match '(?i)\\(AppData|WindowsApps)(\\|$)') { throw 'Per-user/AppData/WindowsApps Python is unsupported. Install Python for all users in a protected directory such as C:\Program Files\Python314.' }
        foreach ($root in $roots) {
            if ($root) {
                $base = [IO.Path]::GetFullPath($root).TrimEnd('\')
                if ($full.Equals($base, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Per-user Python is unsupported. Install Python for all users in a protected directory.'
                }
            }
        }
    }
    return $info
}
