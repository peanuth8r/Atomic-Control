# Run explicitly as a Windows administrator. Never used by installation or CI.
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$ConfigFile, [Parameter(Mandatory)][string]$PythonPath,
      [Parameter(Mandatory)][string]$InstallRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
. (Join-Path $PSScriptRoot 'require-machine-python.ps1')
$python = Assert-AtomicMachinePython -PythonPath $PythonPath
$PythonPath = $python.executable
if (-not $config.PSObject.Properties['python_path'] -or -not ([IO.Path]::GetFullPath($config.python_path)).Equals([IO.Path]::GetFullPath($PythonPath), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The selected Python differs from the enrolled agent. Run the signed runtime updater with the all-users Python first; keep the existing enrollment.'
}
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated' }
$profiles = @($config.profiles)
if ($profiles.Count -lt 1 -or $profiles.Count -gt 2) { throw 'Register one or both supported execution profiles before provisioning.' }
$profileKeys = @($profiles | ForEach-Object { $_.profile_key })
if (@($profileKeys | Select-Object -Unique).Count -ne $profileKeys.Count) { throw 'Duplicate execution profile types are not supported.' }
if (@($profileKeys | Where-Object { $_ -notin @('standard-user', 'local-admin') }).Count -gt 0) { throw 'Unsupported execution profile type.' }
if (-not [IO.Path]::IsPathRooted($PythonPath) -or -not [IO.Path]::IsPathRooted($InstallRoot)) { throw 'Use absolute protected paths' }
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
try { $folder = $service.GetFolder('\AtomicControl') } catch { $folder = $null }
foreach ($profile in $profiles) {
    $id = [guid]::Parse($profile.id).ToString()
    $account = [Security.Principal.NTAccount]::new($profile.account)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($sid -ne $profile.expected_sid) { throw "Provisioned SID differs for $id" }
    if ($profile.profile_key -notin @('standard-user','local-admin') -or $profile.logon_type -ne 'batch') { throw 'Unsupported profile' }
    if (($profile.profile_key -eq 'local-admin') -ne ($profile.privilege -eq 'elevated')) { throw 'Profile privilege mismatch' }
    $profileRoot = Join-Path $config.state_root $id
    $outputRoot = Join-Path $profileRoot 'output'
    if (-not $PSCmdlet.ShouldProcess($profile.account, "Provision fixed batch task $id")) { continue }
    if (-not $folder) { $folder = $service.GetFolder('\').CreateFolder('AtomicControl', 'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)') }
    $folder.SetSecurityDescriptor('O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)', 0)
    New-Item -Path $outputRoot -ItemType Directory -Force | Out-Null
    & icacls.exe $profileRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($sid):(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Profile ACL failed' }
    & icacls.exe $outputRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($sid):(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Output ACL failed' }
    # An existing account is required. Credentials go only to the Windows Task Scheduler API.
    $credential = Get-Credential -UserName $profile.account -Message 'Existing dedicated validation account for password-backed batch task'
    if ($credential.UserName -ne $profile.account) { throw 'Account must match the provisioned profile' }
    $task = $service.NewTask(0)
    $task.RegistrationInfo.Description = 'Atomic Control fixed approved job wrapper'
    $task.Principal.UserId = $sid
    $task.Principal.LogonType = 1 # TASK_LOGON_PASSWORD; never substitute S4U.
    $task.Principal.RunLevel = [int]($profile.privilege -eq 'elevated')
    $task.Settings.MultipleInstances = 2 # IgnoreNew
    $task.Settings.ExecutionTimeLimit = 'PT11M'
    $task.Settings.AllowHardTerminate = $true
    $task.Settings.DisallowStartIfOnBatteries = $false
    $task.Settings.StopIfGoingOnBatteries = $false
    $task.Settings.Enabled = $true
    $action = $task.Actions.Create(0)
    $action.Path = $PythonPath
    $action.WorkingDirectory = $InstallRoot
    $action.Arguments = "-I -m apps.agent.task_wrapper --config `"$ConfigFile`" --profile-id $id"
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
    try {
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        $null = $folder.RegisterTaskDefinition($id, $task, 6, $profile.account, $password, 1, 'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)')
        # Separate fixed token-only probe; never imports or invokes Atomic content.
        $action.Arguments = "-I -m apps.agent.identity_probe --config `"$ConfigFile`" --profile-id $id"
        $null = $folder.RegisterTaskDefinition("$id-identity", $task, 6, $profile.account, $password, 1, 'O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)')
    } finally {
        $password = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        $credential = $null
    }
}
Write-Host 'Tasks provisioned. No test ran. Start AtomicControlAgent and choose Retry validation in the actor details. Do not edit profile validation flags manually.'
