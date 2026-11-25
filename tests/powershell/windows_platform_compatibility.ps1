param([string]$Root, [string]$Work, [string]$Case)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
New-Item -ItemType Directory -Path $Work -Force | Out-Null
$env:ProgramFiles = $Work
$env:WINDIR = $Work
$env:ATOMIC_FIXTURE_WORK = $Work
$nativePlatform = @($IsLinux, $IsMacOS, $IsWindows)
if ($Case -ne 'core') {
    # Emulate 5.1's missing automatic variables in this isolated test process.
    $PSVersionTable.PSEdition = 'Desktop'
    Remove-Variable IsLinux, IsMacOS, IsWindows -Scope Global -Force
}
$wrapper = Join-Path $Work 'invoke_approved_atomic.ps1'
Copy-Item (Join-Path $Root 'apps/agent/powershell/invoke_approved_atomic.ps1') $wrapper
Copy-Item (Join-Path $Root 'apps/agent/powershell/AtomicControlLogger.psm1') $Work
Set-Content (Join-Path $Work 'verify_identity.ps1') @'
param($ExpectedSid, $Privilege)
Set-Content (Join-Path $env:ATOMIC_FIXTURE_WORK 'identity-checked') 'checked'
'@
# A manifest script reproduces upstream's platform-variable reads. The module
# reads them in its separate session state too. No Atomic commands are executed.
Set-Content (Join-Path $Work 'config.ps1') @'
$script:fixturePlatform = if ($IsLinux) { 'linux' } elseif ($IsMacOS) { 'macos' } else { 'windows' }
'@
if ($Case -eq 'strict') {
    Add-Content (Join-Path $Work 'config.ps1') '$null = $AtomicFixtureUndefinedVariable'
}
Set-Content (Join-Path $Work 'fixture.psd1') @'
@{ ModuleVersion = '1.0'; RootModule = 'fixture.psm1'; ScriptsToProcess = @('config.ps1') }
'@
Set-Content (Join-Path $Work 'fixture.psm1') @'
function Invoke-AtomicTest {
    param($Technique, $ExecutionLogPath, $LoggingModule, $PathToAtomicsFolder,
          $TestGuids, $TimeoutSeconds, $Confirm, [switch]$CheckPrereqs)
    @($IsLinux, $IsMacOS, $IsWindows) | ConvertTo-Json |
        Set-Content (Join-Path $env:ATOMIC_FIXTURE_WORK 'platform.json')
    'Prerequisites met:'
}
Export-ModuleMember -Function Invoke-AtomicTest
'@
$manifest = Join-Path $Work 'fixture.psd1'
$pin = (Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Case -eq 'hash') { $pin = '0' * 64 }
@{invoke_module_path=$manifest; invoke_module_sha256=$pin; catalog_root=$Work} |
    ConvertTo-Json | Set-Content (Join-Path $Work 'agent.json')
@{snapshot=@{simulated=$false; action='check'; technique='T1082';
    atomic_guid='aa350376-879f-44d0-8917-f227a38ef2a2'; expected_sid='fixture';
    privilege='standard'; timeout_seconds=10}} |
    ConvertTo-Json | Set-Content (Join-Path $Work 'job.json')
New-Item -ItemType Directory -Path (Join-Path $Work 'output') | Out-Null
$failure = $null
try { & $wrapper -JobFile (Join-Path $Work 'job.json') -ConfigFile (Join-Path $Work 'agent.json') }
catch { $failure = $_ }
if (-not (Test-Path (Join-Path $Work 'identity-checked'))) { throw 'Identity verification was skipped' }
if ($Case -eq 'hash') {
    if ($null -eq $failure -or $failure.ToString() -notmatch 'module hash mismatch') { throw 'Module pin was not enforced' }
} elseif ($Case -eq 'strict') {
    if ($null -eq $failure -or $failure.ToString() -notmatch 'AtomicFixtureUndefinedVariable') { throw 'Strict mode was weakened' }
} else {
    if ($null -ne $failure) { throw $failure }
    $platform = @(Get-Content (Join-Path $Work 'platform.json') -Raw | ConvertFrom-Json)
    $expected = if ($Case -eq 'core') { $nativePlatform } else { @($false, $false, $true) }
    if (($platform -join ',') -ne ($expected -join ',')) { throw 'Incorrect module platform values' }
    if ($Case -eq 'core' -and (Get-Variable IsLinux).Options -notmatch 'ReadOnly') { throw 'Core automatic variables were replaced' }
    $evidence = Get-Content (Join-Path $Work 'output/atomic-evidence.json') -Raw | ConvertFrom-Json
    if ($evidence.status -ne 'passed') { throw 'Fixture check did not complete' }
}
if ($Case -in @('hash', 'strict') -and (Test-Path (Join-Path $Work 'platform.json'))) { throw 'Fixture command ran after verification failed' }
Write-Output "Passed $Case"
