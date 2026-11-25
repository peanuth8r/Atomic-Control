# Actor-specific source installer. Run only on the named, authorized Windows validation host.
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$PythonPath,
      [string]$InstallRoot = (Join-Path $env:ProgramFiles 'AtomicControl'),
      [switch]$SkipCATrust,
      [switch]$StartService)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as administrator.' }
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run this installer in Administrator Windows PowerShell 5.1 so execution dependencies are installed for the agent execution environment.' }
$bootstrapFile = Join-Path $PSScriptRoot 'bootstrap.json'
$bootstrap = Get-Content -LiteralPath $bootstrapFile -Raw | ConvertFrom-Json
if ($bootstrap.mode -ne 'enrollment') { throw 'Configuration-only package. Generate an enrollment package from a real HTTPS control plane before installing.' }
$network = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$localNames = @($env:COMPUTERNAME, $network.HostName)
if ($network.DomainName) { $localNames += "$($network.HostName).$($network.DomainName)" }
if ($localNames -notcontains $bootstrap.hostname) { throw 'This package belongs to a different Windows host.' }
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($bootstrap.expires_at -le $now) { throw 'Enrollment expired. Generate a new package from the Actors page.' }
. (Join-Path $PSScriptRoot 'runtime\scripts\require-machine-python.ps1')
$info = Assert-AtomicMachinePython -PythonPath $PythonPath
$PythonPath = $info.executable
if (-not [IO.Path]::IsPathRooted($InstallRoot)) { throw 'Use an absolute protected installation directory.' }
$packageConfig = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'agent.json') -Raw | ConvertFrom-Json
if ($packageConfig.revision -and -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'catalog.json') -PathType Leaf)) { throw 'Selected catalog metadata is missing. Generate a fresh agent package.' }
$service = Get-Service -Name AtomicControlAgent -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') { throw 'Stop the existing service and verify no execution is active before replacing it.' }
$stateRoot = Join-Path $env:ProgramData 'AtomicControl'
if (Test-Path -LiteralPath (Join-Path $stateRoot 'jobs\active.json')) { throw 'An unreconciled job journal exists. Reconcile the host before installing.' }
# Internal checksums detect damage. Compare the downloaded ZIP hash with the value shown by the HTTPS UI.
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.actor_id -ne $bootstrap.actor_id -or $manifest.hostname -ne $bootstrap.hostname) { throw 'Package manifest identity mismatch.' }
$bundleRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
foreach ($entry in $manifest.files.PSObject.Properties) {
    $path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $entry.Name))
    if (-not $path.StartsWith($bundleRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid package manifest path.' }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw "Package integrity check failed: $($entry.Name)" }
}
$caCertificate = $null
if ($bootstrap.PSObject.Properties['public_ca'] -and $bootstrap.public_ca) {
    $ca = $bootstrap.public_ca
    if ($ca.filename -ne 'atomic-control-ca.crt' -or $ca.store -ne 'LocalMachine\Root' -or $ca.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid public CA metadata.' }
    if (-not $manifest.files.PSObject.Properties['atomic-control-ca.crt']) { throw 'The bundled CA must be covered by the package manifest.' }
    $caPath = Join-Path $PSScriptRoot 'atomic-control-ca.crt'
    $caCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($caPath)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = -join ($sha256.ComputeHash($caCertificate.RawData) | ForEach-Object { $_.ToString('X2') }) } finally { $sha256.Dispose() }
    $basic = $caCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    $usage = $caCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' }
    if (-not $basic -or -not $usage) { throw 'The bundled certificate lacks CA constraints or key usage.' }
    $basic = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($basic, $basic.Critical)
    $usage = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $usage.Critical)
    if ($fingerprint -ne $ca.sha256 -or $caCertificate.HasPrivateKey -or -not $basic.CertificateAuthority -or
        -not ($usage.KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign) -or
        $caCertificate.Subject -ne $caCertificate.Issuer -or
        $caCertificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $caCertificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'The bundled public CA is invalid or its fingerprint changed.' }
    Write-Host "Control-plane CA: $($caCertificate.Subject)"
    Write-Host "Certificate SHA-256: $fingerprint"
}
$action = 'Verify HTTPS, install Python dependencies and the pinned Invoke-AtomicRedTeam framework with its all-users YAML dependency, enroll this actor, and install its stopped Windows service'
if ($caCertificate -and -not $SkipCATrust) { $action = 'Trust the bundled control-plane CA in LocalMachine\Root; ' + $action }
if ($StartService) { $action += '; start the service for heartbeat and approved-job polling' }
if (-not $PSCmdlet.ShouldProcess($bootstrap.hostname, $action)) { return }
if ($caCertificate -and -not $SkipCATrust) {
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $existing = $store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $caCertificate.Thumbprint, $false)
        if ($existing.Count -eq 0) {
            $store.Add($caCertificate)
            Write-Host 'Trusted the bundled CA for this computer, including the LocalSystem agent service.'
        } else { Write-Host 'The bundled control-plane CA is already trusted on this computer.' }
    } finally { $store.Close(); $store.Dispose() }
}
# Verify the same native trust settings as the agent before installing dependencies or enrolling.
$healthCheck = @'
import json, os, ssl, sys
from urllib.request import HTTPRedirectHandler, HTTPSHandler, build_opener
class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('Control-plane HTTPS redirects are not accepted')
context = ssl.create_default_context(cafile=os.environ.get('SSL_CERT_FILE'), capath=os.environ.get('SSL_CERT_DIR'))
opener = build_opener(HTTPSHandler(context=context), NoRedirects())
with opener.open(sys.argv[1].rstrip('/') + '/health', timeout=10) as response:
    result = json.load(response)
if result.get('status') != 'ok' or result.get('mode') != 'real':
    raise RuntimeError('Expected a healthy real-mode control plane')
'@
& $PythonPath -I -c $healthCheck $bootstrap.api_url
if ($LASTEXITCODE -ne 0) { throw 'Verified HTTPS preflight failed. Check hostname, CA trust and SSL_CERT_FILE/SSL_CERT_DIR overrides. No enrollment was attempted.' }
New-Item -Path $InstallRoot -ItemType Directory -Force | Out-Null
& icacls.exe $InstallRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the installation directory.' }
$runtime = Join-Path $InstallRoot 'runtime'
New-Item -Path $runtime -ItemType Directory -Force | Out-Null
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'runtime') -Force | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $runtime -Recurse -Force }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'job-signing-public.pem') -Destination (Join-Path $InstallRoot 'job-signing-public.pem') -Force
if ($caCertificate) { Copy-Item -LiteralPath $caPath -Destination (Join-Path $InstallRoot 'atomic-control-ca.crt') -Force }
# Dependency installation is explicit. Supply approved local wheels / pip configuration for offline hosts.
& $PythonPath -I -m pip install -r (Join-Path $runtime 'requirements-agent.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
$postInstall = Join-Path $info.paths.scripts 'pywin32_postinstall.py'
if (-not (Test-Path -LiteralPath $postInstall -PathType Leaf)) { throw 'The pywin32 post-install script was not installed into the machine-wide Python Scripts directory.' }
& $PythonPath $postInstall -install
if ($LASTEXITCODE -ne 0) { throw 'Windows service support installation failed.' }
& $PythonPath -I -m pip install --no-deps --no-build-isolation $runtime
if ($LASTEXITCODE -ne 0) { throw 'Agent package installation failed.' }
# Prepare framework settings in a protected local copy; retain the downloaded
# package's integrity-covered agent.json and enroll only after setup succeeds.
New-Item -Path $stateRoot -ItemType Directory -Force | Out-Null
& icacls.exe $stateRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the agent state directory.' }
$preparedConfigFile = Join-Path $InstallRoot ('.enrollment-config-' + [guid]::NewGuid().ToString('N') + '.json')
$preparedConfig = $packageConfig.PSObject.Copy()
$preparedConfig | Add-Member -NotePropertyName python_path -NotePropertyValue $PythonPath -Force
$preparedConfig.state_root = Join-Path $stateRoot 'jobs'
[IO.File]::WriteAllText($preparedConfigFile, ($preparedConfig | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
Push-Location $runtime
try {
    & (Join-Path $runtime 'scripts\install-windows-execution-prerequisites.ps1') -ConfigFile $preparedConfigFile -InstallRoot $InstallRoot -PrepareForEnrollment -Confirm:$false
    if ($packageConfig.revision) {
        & $PythonPath -I -m apps.agent.windows_catalog --config $preparedConfigFile --manifest (Join-Path $PSScriptRoot 'catalog.json') --install-root $InstallRoot
        if ($LASTEXITCODE -ne 0) { throw 'Catalog installation/verification failed. No enrollment was attempted. Resolve Git/catalog setup, then use a fresh package if the token expired.' }
    } elseif ($packageConfig.PSObject.Properties['delivery_mode'] -and $packageConfig.delivery_mode -eq 'on_demand') { Write-Host 'On-demand delivery: no catalog checkout or Git required. Tests download only for their current attempt.' } else { Write-Host 'No catalog selected: enrolling for connectivity only. Select an imported revision when generating a test-ready package.' }
    & $PythonPath -I -m apps.agent.bootstrap --bootstrap $bootstrapFile --config $preparedConfigFile --install-root $InstallRoot --state-root $stateRoot
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment/configuration failed. The service was not started. Regenerate the package if the token expired.' }
    $serviceAction = 'install'
    if ($service) { $serviceAction = 'update' }
    & $PythonPath -I -m apps.agent.service --startup auto $serviceAction
    if ($LASTEXITCODE -ne 0) { throw 'Windows service registration failed.' }
} finally {
    Pop-Location
    Remove-Item -LiteralPath $preparedConfigFile -Force -ErrorAction SilentlyContinue
}
Write-Host 'Agent installed and enrolled. The installer did not invoke an Atomic test.'
if ($StartService) {
    Start-Service -Name AtomicControlAgent -ErrorAction Stop
    Write-Host 'Agent service started for heartbeat and approved-job polling.'
} else { Write-Host 'The service remains stopped. Use -StartService or start AtomicControlAgent explicitly when ready.' }
Write-Host 'The pinned Invoke-AtomicRedTeam framework and all-users YAML dependency are ready. Profiles synchronize automatically while idle. Provision required password-backed profile tasks locally, then choose Retry validation in actor details and enable the actor if disabled.'
