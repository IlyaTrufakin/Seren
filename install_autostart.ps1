# Install for the current Windows user; does not start PLC or applications now.
$ErrorActionPreference = 'Stop'
$serenRoot = $PSScriptRoot
$serenPython = Join-Path $serenRoot '.venv\Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $serenPython)) { throw 'Python virtual environment is missing.' }
$serenUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$serenAction = New-ScheduledTaskAction -Execute $serenPython -Argument '-m src.system_supervisor' -WorkingDirectory $serenRoot
$serenTrigger = New-ScheduledTaskTrigger -AtLogOn -User $serenUser
$serenPrincipal = New-ScheduledTaskPrincipal -UserId $serenUser -LogonType Interactive -RunLevel Limited
$serenSettings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
try {
    Register-ScheduledTask -TaskName 'SerenSystem' -Action $serenAction -Trigger $serenTrigger -Principal $serenPrincipal -Settings $serenSettings -Description 'Seren main, monitor1654 and radar_kharkov with independent crash recovery' -Force | Out-Null
    Write-Output 'Installed scheduled task SerenSystem; starts on next user login. Applications have not been started.'
} catch {
    $serenStartup = [Environment]::GetFolderPath('Startup')
    $serenShell = New-Object -ComObject WScript.Shell
    $serenShortcut = $serenShell.CreateShortcut((Join-Path $serenStartup 'SerenSystem.lnk'))
    $serenShortcut.TargetPath = $serenPython
    $serenShortcut.Arguments = '-m src.system_supervisor'
    $serenShortcut.WorkingDirectory = $serenRoot
    $serenShortcut.WindowStyle = 7
    $serenShortcut.Save()
    Write-Output 'Installed current-user Startup shortcut SerenSystem; starts on next login. Applications have not been started. Task Scheduler was unavailable; child process recovery remains active.'
}
