# Installs the pinned execution framework only. Never invokes an Atomic test.
[CmdletBinding(SupportsShouldProcess)]
param([string]$ConfigFile = 'C:\ProgramData\AtomicControl\agent.json',
      [string]$InstallRoot = (Join-Path $env:ProgramFiles 'AtomicControl'),
      [switch]$PrepareForEnrollment)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AtomicFrameworkTree {
    param([string]$Source, [string]$Destination, [string[]]$AllowedExtraFiles = @())
    $sourcePrefix = $Source.TrimEnd([char[]]'\/') + [IO.Path]::DirectorySeparatorChar
    $destinationPrefix = $Destination.TrimEnd([char[]]'\/') + [IO.Path]::DirectorySeparatorChar
    $expected = @{}
    foreach ($file in Get-ChildItem -LiteralPath $Source -Recurse -File -Force) {
        $relative = $file.FullName.Substring($sourcePrefix.Length)
        $expected[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    $pending = @((Get-Item -LiteralPath $Destination -Force))
    $found = 0
    while ($pending.Count -gt 0) {
        $entry = $pending[0]
        $pending = @($pending | Select-Object -Skip 1)
        if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Execution framework paths cannot contain links or reparse points.' }
        if ($entry.PSIsContainer) {
            $pending += @(Get-ChildItem -LiteralPath $entry.FullName -Force)
        } else {
            $relative = $entry.FullName.Substring($destinationPrefix.Length)
            if ($expected.ContainsKey($relative)) {
                if ((Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) { throw "Existing execution framework differs from the pinned source: $relative. Files were retained." }
                $found++
            } elseif ($relative -notin $AllowedExtraFiles) {
                throw "Unexpected execution framework file: $relative. Files were retained."
            }
        }
    }
    if ($found -ne $expected.Count) { throw 'The existing execution framework is incomplete. Files were retained.' }
}

function Protect-AtomicFrameworkTree {
    param([string]$Directory)
    $acl = Get-Acl -LiteralPath $Directory
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)')
    Set-Acl -LiteralPath $Directory -AclObject $acl
    foreach ($entry in Get-ChildItem -LiteralPath $Directory -Force) {
        & icacls.exe $entry.FullName /reset /T | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Framework permissions could not be reset to protected inheritance.' }
    }
    & icacls.exe $Directory /setowner '*S-1-5-32-544' /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Framework ownership setup failed.' }
}

function Install-AtomicYamlDependency {
    param([string]$Stage)
    # Fetch the exact Gallery package directly: no NuGet bootstrap, trust-policy
    # mutation, CurrentUser install, or interactive repository prompt is needed.
    $archive = Join-Path $Stage 'yaml.zip'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/package/powershell-yaml/0.4.12' -OutFile $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'd4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810') { throw 'Pinned YAML package checksum mismatch.' }
    $unpacked = Join-Path $Stage 'yaml-package'
    Expand-Archive -LiteralPath $archive -DestinationPath $unpacked
    $source = Join-Path $Stage 'yaml-runtime'
    New-Item -ItemType Directory -Path $source | Out-Null
    foreach ($name in @('powershell-yaml.psd1', 'powershell-yaml.psm1', 'lib', 'LICENSE', 'README.md')) {
        Copy-Item -LiteralPath (Join-Path $unpacked $name) -Destination $source -Recurse
    }
    $destination = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\powershell-yaml\0.4.12'
    $metadata = @('PSGetModuleInfo.xml', 'build.ps1', 'powershell-yaml.nuspec', ('Tests' + [IO.Path]::DirectorySeparatorChar + 'powershell-yaml.Tests.ps1'))
    Install-AtomicVerifiedTree -Source $source -Destination $destination -AllowedExtraFiles $metadata
    $null = Test-ModuleManifest -Path (Join-Path $destination 'powershell-yaml.psd1') -ErrorAction Stop
}

function Install-AtomicVerifiedTree {
    param([string]$Source, [string]$Destination, [string[]]$AllowedExtraFiles = @())
    if (Test-Path -LiteralPath $Destination) {
        Assert-AtomicFrameworkTree -Source $Source -Destination $Destination -AllowedExtraFiles $AllowedExtraFiles
        Protect-AtomicFrameworkTree -Directory $Destination
        Write-Host "Reusing verified execution dependency: $Destination"
        return
    }
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = Join-Path $parent ('.execution-module-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporary | Out-Null
    try {
        foreach ($entry in Get-ChildItem -LiteralPath $Source -Force) {
            Copy-Item -LiteralPath $entry.FullName -Destination $temporary -Recurse
        }
        Assert-AtomicFrameworkTree -Source $Source -Destination $temporary
        Protect-AtomicFrameworkTree -Directory $temporary
        # Directory.Move refuses an existing destination instead of merging
        # into a directory that appeared during setup. Publish complete trees.
        [IO.Directory]::Move($temporary, $Destination)
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    }
}

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run Windows PowerShell as administrator.' }
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run this helper in Windows PowerShell 5.1 so the YAML dependency installs where the agent execution wrapper can find it.' }
$config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
. (Join-Path $PSScriptRoot 'require-machine-python.ps1')
$python = Assert-AtomicMachinePython -PythonPath $config.python_path
$service = Get-Service -Name AtomicControlAgent -ErrorAction SilentlyContinue
if (-not $service -and -not $PrepareForEnrollment) { throw 'The enrolled agent service is missing. Use Install-Agent.ps1 for a new installation.' }
if ($service -and $service.Status -ne 'Stopped') { throw 'Finish/reconcile active work and stop AtomicControlAgent before changing execution prerequisites.' }
if (Test-Path -LiteralPath (Join-Path $config.state_root 'active.json')) { throw 'An execution journal requires reconciliation before setup.' }
if (-not [IO.Path]::IsPathRooted($InstallRoot)) { throw 'Use an absolute protected installation root.' }
$destination = Join-Path $InstallRoot 'Invoke-AtomicRedTeam'
$revision = '8af478bb9e4637df568ac1e596553b025b16cd1b'
$archiveHash = '778489daf0a961478ff2716e556958817e22d29962d717b200b3d2b21eafb281'
$manifestHash = '3ec05509a96193aa9e09cb9f2a37f68956e27edffbc851eecf9ebb458e23b513'
if (-not $PSCmdlet.ShouldProcess($destination, "Install or verify official Invoke-AtomicRedTeam revision $revision and powershell-yaml 0.4.12 for all users; update only the module path/hash")) { return }
$stage = Join-Path (Split-Path -Parent $ConfigFile) ('.execution-setup-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
& icacls.exe $stage /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Staging ACL setup failed.' }
try {
    $archive = Join-Path $stage 'invoke.zip'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri "https://codeload.github.com/redcanaryco/invoke-atomicredteam/zip/$revision" -OutFile $archive
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) { throw 'Pinned framework archive checksum mismatch.' }
    Expand-Archive -LiteralPath $archive -DestinationPath $stage
    $source = Join-Path $stage "invoke-atomicredteam-$revision"
    if ((Get-FileHash -LiteralPath (Join-Path $source 'Invoke-AtomicRedTeam.psd1') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifestHash) { throw 'Pinned module manifest checksum mismatch.' }
    Install-AtomicVerifiedTree -Source $source -Destination $destination
    # Scope AllUsers is needed because execution uses a different local account.
    Install-AtomicYamlDependency -Stage $stage
    $module = Join-Path $destination 'Invoke-AtomicRedTeam.psd1'
    if ((Get-FileHash -LiteralPath $module -Algorithm SHA256).Hash.ToLowerInvariant() -ne $manifestHash) { throw 'Installed module checksum mismatch.' }
    $previousModulePath = $env:PSModulePath
    try {
        $env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;$env:WINDIR\System32\WindowsPowerShell\v1.0\Modules"
        $null = Test-ModuleManifest -Path $module -ErrorAction Stop
    } finally { $env:PSModulePath = $previousModulePath }
    # The existing agent performs protected atomic writes. Do not serialize its
    # configuration through PowerShell or replace enrollment/profile settings.
    $program = @'
import json, sys
from pathlib import Path
from uuid import uuid4
from apps.agent.windows_profile_sync import protected, write_config
path = Path(sys.argv[1])
protected(path)
config = json.loads(path.read_text())
if sys.argv[4] != 'prepare':
    write_config(path.with_name('agent.before-execution-setup-' + uuid4().hex + '.json'), config, readable=False)
config.update(invoke_module_path=sys.argv[2], invoke_module_sha256=sys.argv[3])
write_config(path, config)
'@
    $mode = if ($PrepareForEnrollment) { 'prepare' } else { 'repair' }
    & $python.executable -I -c $program $ConfigFile $module $manifestHash $mode
    if ($LASTEXITCODE -ne 0) { throw 'Configuration update failed; leave the service stopped and inspect the retained module before retrying.' }
    Write-Host "Installed framework revision $revision and configured manifest SHA-256 $manifestHash."
    Write-Host 'Execution framework setup completed. The service remains stopped. No Atomic test or per-test prerequisite command ran.'
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
