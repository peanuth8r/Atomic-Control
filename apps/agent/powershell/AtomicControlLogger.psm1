# Fixed logger contract used by Invoke-AtomicRedTeam. No commands are evaluated here.
function Start-ExecutionLog { }
function Stop-ExecutionLog { }
function Write-ExecutionLog {
    param($Start, $End, $Technique, $Number, $Name, $Guid, $Executor, $Description,
          $Command, $LogPath, $Hostname, $User, $Result, $IsWindows)
    if ($null -eq $Result.ExitCode) { throw 'Atomic execution returned no exit evidence' }
    @{ atomic_guid = [string]$Guid; exit_code = [int]$Result.ExitCode;
       started_utc = $Start.ToUniversalTime().ToString('o');
       finished_utc = $End.ToUniversalTime().ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $LogPath -Encoding UTF8
}
Export-ModuleMember -Function Start-ExecutionLog, Stop-ExecutionLog, Write-ExecutionLog
