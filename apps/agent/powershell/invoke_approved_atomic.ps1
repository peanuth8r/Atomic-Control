# Fixed installed wrapper. Invoked only by the token-verified task wrapper.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$JobFile, [Parameter(Mandatory)][string]$ConfigFile)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$job = Get-Content -LiteralPath $JobFile -Raw | ConvertFrom-Json
$config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
$s = $job.snapshot
if ($s.simulated -or $s.action -notin @('execute', 'check', 'cleanup')) { throw 'Invalid real execution action' }
if ($s.technique -notmatch '^T\d{4}(\.\d{3})?$') { throw 'Invalid technique' }
$guid = [guid]::Parse($s.atomic_guid).ToString()
# Recheck the token in the same PowerShell process before importing the pinned module.
& (Join-Path $PSScriptRoot 'verify_identity.ps1') -ExpectedSid $s.expected_sid -Privilege $s.privilege
if ((Get-FileHash -LiteralPath $config.invoke_module_path -Algorithm SHA256).Hash.ToLower() -ne $config.invoke_module_sha256) { throw 'Invoke-AtomicRedTeam module hash mismatch' }
# Exclude profile-writable module locations from dependency resolution.
$env:PSModulePath = "$env:ProgramFiles\WindowsPowerShell\Modules;$env:WINDIR\System32\WindowsPowerShell\v1.0\Modules"
# Invoke-AtomicRedTeam references Core platform variables even on Windows PowerShell
# 5.1. Global scope makes them visible to its manifest's ScriptsToProcess and module
# session state under StrictMode. Each job has its own PowerShell process; preserve
# Core's native, read-only variables when running in that edition.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $global:IsLinux = $false
    $global:IsMacOS = $false
    $global:IsWindows = $true
}
Import-Module -Name (Join-Path $PSScriptRoot 'AtomicControlLogger.psm1') -Force -ErrorAction Stop
Import-Module -Name $config.invoke_module_path -Force -ErrorAction Stop
$evidencePath = Join-Path (Join-Path (Split-Path -Parent $JobFile) 'output') 'atomic-evidence.json'
if (Test-Path -LiteralPath $evidencePath) { Remove-Item -LiteralPath $evidencePath -Force }
$catalogRoot = $config.catalog_root
if ($s.PSObject.Properties['artifact'] -and $s.artifact) {
    $attempt = [guid]::Parse($job.attempt_id).ToString()
    $catalogRoot = Join-Path (Join-Path (Join-Path $config.state_root 'downloads') $attempt) 'payload'
}
$arguments = @{
    ExecutionLogPath = $evidencePath
    LoggingModule = 'AtomicControlLogger' 
    PathToAtomicsFolder = (Join-Path $catalogRoot 'atomics')
    TestGuids = @($guid)
    TimeoutSeconds = [int]$s.timeout_seconds
    Confirm = $false
}
# No GetPrereqs, arbitrary overrides, command strings, or remote invocation.
switch ($s.action) {
    'check' {
        $records = @(Invoke-AtomicTest $s.technique @arguments -CheckPrereqs -ErrorAction Stop 6>&1)
        $text = ($records | ForEach-Object { $_.ToString() }) -join "`n"
        Write-Output $text
        if ($text -match 'Prerequisites not met:') {
            @{ status = 'missing'; requirements = @($text -split "`n" | Where-Object { $_ -match '\[\*\]' }) } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding UTF8
            exit 1
        }
        if ($text -notmatch 'Prerequisites met:') { throw 'No conclusive prerequisite evidence returned' }
        @{ status = 'passed'; requirements = @() } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    }
    'execute' {
        Invoke-AtomicTest $s.technique @arguments -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $evidencePath)) { throw 'No Atomic exit evidence returned' }
        $evidence = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
        if ($evidence.atomic_guid -ne $guid) { throw 'Atomic log GUID mismatch' }
        exit ([int]$evidence.exit_code)
    }
    'cleanup' { Invoke-AtomicTest $s.technique @arguments -Cleanup -ErrorAction Stop }
}
if (-not $?) { exit 1 }
