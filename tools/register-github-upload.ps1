param([switch]$RunUpload)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$aetherProject = Split-Path $PSScriptRoot -Parent
$aetherTaskName = 'Aether Weekly GitHub Upload'

if ($RunUpload) {
    . (Join-Path $PSScriptRoot 'common.ps1')
    $aetherUploadLease = $null
    try {
        $aetherUploadLease = Enter-AetherBuildTestLease
        $env:PATH += ';C:\Program Files\Git\cmd'
        $aetherPython = Get-Command python.exe -ErrorAction Stop
        & $aetherPython.Source -B (Join-Path $PSScriptRoot 'publish-source.py') --publish --log
        $aetherUploadExit = $LASTEXITCODE
    } finally {
        if ($null -ne $aetherUploadLease) {
            $aetherUploadLease.ReleaseMutex()
            $aetherUploadLease.Dispose()
        }
    }
    exit $aetherUploadExit
}

# A floating local-time trigger follows Sydney daylight saving automatically.
# Refuse a changed host zone instead of silently choosing a different 18:00.
if ((Get-TimeZone).Id -ne 'AUS Eastern Standard Time') {
    throw 'The weekly task requires this Windows host to use the Sydney time zone.'
}
$aetherPython = Get-Command python.exe -ErrorAction Stop
& $aetherPython.Source -B (Join-Path $PSScriptRoot 'publish-source.py')
if ($LASTEXITCODE -ne 0) { throw 'Source upload preview failed; task was not registered.' }
$aetherIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $aetherUser = $aetherIdentity.Name } finally { $aetherIdentity.Dispose() }
$aetherPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$aetherArguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -RunUpload'
$aetherAction = New-ScheduledTaskAction -Execute $aetherPowerShell -Argument $aetherArguments -WorkingDirectory $aetherProject
$aetherTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Friday -At '18:00'
$aetherTrigger.StartBoundary = ([datetime]::Parse($aetherTrigger.StartBoundary)).ToString('yyyy-MM-ddTHH:mm:ss')
$aetherPrincipal = New-ScheduledTaskPrincipal -UserId $aetherUser -LogonType Interactive -RunLevel Limited
$aetherSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$aetherExisting = Get-ScheduledTask -TaskName $aetherTaskName -ErrorAction SilentlyContinue
if ($null -ne $aetherExisting) {
    if ($aetherExisting.Actions.Count -ne 1 -or $aetherExisting.Actions[0].Arguments -ne $aetherArguments -or
        $aetherExisting.Actions[0].WorkingDirectory -ne $aetherProject) {
        throw 'A task with this name belongs to another action; it was not overwritten.'
    }
}
Register-ScheduledTask -TaskName $aetherTaskName -Action $aetherAction -Trigger $aetherTrigger `
    -Principal $aetherPrincipal -Settings $aetherSettings -Force `
    -Description 'Upload only Aether project source and README to DillonHarvey/aether-android, Fridays at 18:00 Sydney time. Requires this signed-in user and GitHub credentials; missed runs start when available. No test or document upload.' | Out-Null
Get-ScheduledTask -TaskName $aetherTaskName | Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName $aetherTaskName | Select-Object NextRunTime, LastTaskResult
