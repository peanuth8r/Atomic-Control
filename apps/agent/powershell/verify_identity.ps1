[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExpectedSid, [Parameter(Mandatory)][ValidateSet('standard','elevated')][string]$Privilege)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne $ExpectedSid) { throw 'SID mismatch' }
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$hasAdminGroup = @($identity.Groups | Where-Object { $_.Value -eq 'S-1-5-32-544' }).Count -gt 0
# IsInRole measures enabled membership. Independent full token elevation and integrity inspection occurs in Python.
if ($Privilege -eq 'standard' -and ($hasAdminGroup -or $isAdmin)) { throw 'Standard identity has administrator membership' }
if ($Privilege -eq 'elevated' -and -not $isAdmin) { throw 'Administrator token is not enabled' }
