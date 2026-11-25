[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$PythonPath, [Parameter(Mandatory)][string]$InstallRoot)
$ErrorActionPreference = 'Stop'
if (-not $PSCmdlet.ShouldProcess('AtomicControlAgent', 'Stop and remove service and scheduled tasks; retain evidence')) { return }
$service = Get-Service -Name AtomicControlAgent -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') { Stop-Service AtomicControlAgent }
Push-Location $InstallRoot
try { & $PythonPath -m apps.agent.service remove } finally { Pop-Location }
Get-ScheduledTask -TaskPath '\AtomicControl\' -ErrorAction SilentlyContinue | ForEach-Object { Stop-ScheduledTask -InputObject $_ -ErrorAction SilentlyContinue; Unregister-ScheduledTask -InputObject $_ -Confirm:$false }
Write-Host 'Service and tasks removed. Revoke server credentials and disable actor separately. Catalog, evidence, accounts and config retained.'
