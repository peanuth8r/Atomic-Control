[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$InstallRoot, [Parameter(Mandatory)][string]$ConfigFile,
      [Parameter(Mandatory)][string]$PythonPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated' }
$config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
if ($config.api_url -notlike 'https://*') { throw 'Agent API requires HTTPS' }
if (-not $PSCmdlet.ShouldProcess($InstallRoot, 'Install AtomicControlAgent service without starting it')) { return }
$root = Join-Path $env:ProgramData 'AtomicControl'
New-Item -Path $root -ItemType Directory -Force | Out-Null
# Protect installation, catalog, signing public key, module, Python and its dependencies from profile writes.
& icacls.exe $InstallRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Installation ACL failed' }
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'State ACL failed' }
Copy-Item -LiteralPath $ConfigFile -Destination (Join-Path $root 'agent.json') -Force
# Install the importable package so pythonservice.exe can resolve apps.agent from System32.
& $PythonPath -m pip install --no-deps $InstallRoot
if ($LASTEXITCODE -ne 0) { throw 'Python package installation failed' }
Push-Location $InstallRoot
try { & $PythonPath -m apps.agent.service --startup auto install; if ($LASTEXITCODE -ne 0) { throw 'Service install failed' } } finally { Pop-Location }
# Credentials must be enrolled separately into a SYSTEM-only directory using DPAPI.
Write-Host 'Installed stopped. Complete enrollment and profile provisioning, then start AtomicControlAgent explicitly.'
