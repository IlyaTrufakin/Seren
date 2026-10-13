# Pre-logon background runtime. Installs tasks, does not start production PLC now.
$ErrorActionPreference='Stop'
$serenRoot=$PSScriptRoot
$serenPython=Join-Path $serenRoot '.venv\Scripts\pythonw.exe'
$serenRuntime=Join-Path $serenRoot 'runtime'
$serenBackgroundConfig=Join-Path $serenRoot 'config_background.json'
if (-not (Test-Path -LiteralPath $serenBackgroundConfig)) { [IO.File]::WriteAllText($serenBackgroundConfig,'{"enabled":false}',[Text.UTF8Encoding]::new($false)) }
if (-not (Test-Path -LiteralPath $serenPython)) {throw 'Python environment missing'}
$serenPrincipal=New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\NETWORK SERVICE' -LogonType ServiceAccount -RunLevel Limited
$serenSettings=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
# Only read/execute source; write permission is limited to state and logs.
& icacls.exe $serenRoot /grant '*S-1-5-20:RX' /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'Cannot grant background account project traversal'}
foreach ($serenSource in @('src','.venv','profiles')) {
    & icacls.exe (Join-Path $serenRoot $serenSource) /grant '*S-1-5-20:(OI)(CI)RX' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'Cannot grant background account dependency access'}
}
foreach ($serenFile in @('config.json','config_main.json','config_analyzers.json','config_background.json')) {
    & icacls.exe (Join-Path $serenRoot $serenFile) /grant '*S-1-5-20:R' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'Cannot grant background account config access'}
}
$serenConfig=Get-Content (Join-Path $serenRoot 'config_main.json') -Raw | ConvertFrom-Json
$serenKey=[IO.Path]::GetFullPath((Join-Path $serenRoot $serenConfig.alarmmap_key_file))
if (-not $serenKey.StartsWith($serenRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'API key must be inside project for this installer'}
& icacls.exe (Split-Path $serenKey) /grant '*S-1-5-20:RX' /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'Cannot grant API folder traversal'}
& icacls.exe $serenKey /grant '*S-1-5-20:R' /Q | Out-Null
if ($LASTEXITCODE -ne 0) {throw 'Cannot grant configured API key access'}
foreach ($serenFolder in @('runtime','logs')) {
    $serenPath=Join-Path $serenRoot $serenFolder
    New-Item -ItemType Directory -Path $serenPath -Force | Out-Null
    & icacls.exe $serenPath /grant '*S-1-5-20:(OI)(CI)M' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) {throw 'Cannot grant background account state/log access'}
}
$serenProbeFile=Join-Path $serenRuntime 'background_probe.json'
if (Test-Path -LiteralPath $serenProbeFile) {Remove-Item -LiteralPath $serenProbeFile}
$serenProbeAction=New-ScheduledTaskAction -Execute $serenPython -Argument '-m src.background_runner --probe' -WorkingDirectory $serenRoot
$serenProbeSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'SerenBackgroundProbe' -Action $serenProbeAction -Principal $serenPrincipal -Settings $serenProbeSettings -Force | Out-Null
try {
Start-ScheduledTask -TaskName 'SerenBackgroundProbe'
$serenDeadline=(Get-Date).AddSeconds(45)
while (-not (Test-Path -LiteralPath $serenProbeFile) -and (Get-Date) -lt $serenDeadline) {Start-Sleep -Milliseconds 500}
if (-not (Test-Path -LiteralPath $serenProbeFile)) {throw 'Background account probe did not complete'}
$serenProbe=Get-Content -LiteralPath $serenProbeFile -Raw | ConvertFrom-Json
if (-not $serenProbe.data.ok) {throw ('Background account probe failed: '+$serenProbe.data.error)}
} finally {
    Unregister-ScheduledTask -TaskName 'SerenBackgroundProbe' -Confirm:$false -ErrorAction SilentlyContinue
}
$serenAction=New-ScheduledTaskAction -Execute $serenPython -Argument '-m src.system_supervisor --background' -WorkingDirectory $serenRoot
$serenTrigger=New-ScheduledTaskTrigger -AtStartup
$serenTrigger.Delay='PT20S'
Register-ScheduledTask -TaskName 'SerenBackground' -Action $serenAction -Trigger $serenTrigger -Principal $serenPrincipal -Settings $serenSettings -Description 'Seren API/PLC and both Telegram engines before user login' -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $serenRoot 'config_background.json'),'{"enabled":true}',[Text.UTF8Encoding]::new($false))
# SerenSystem login task opens viewer windows; background controls continue independently.
[IO.File]::WriteAllText((Join-Path $serenRuntime 'background_install_result.json'),'{"installed":true,"probe_passed":true,"production_started":false}',[Text.UTF8Encoding]::new($false))
Write-Output 'Installed SerenBackground at OS startup (NETWORK SERVICE); pre-logon probe passed. Production starts on next reboot; no PLC started by installer.'
