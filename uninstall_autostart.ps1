$ErrorActionPreference='Stop'
$serenTask=Get-ScheduledTask -TaskName 'SerenSystem' -ErrorAction SilentlyContinue
if ($serenTask) { Unregister-ScheduledTask -TaskName 'SerenSystem' -Confirm:$false }
$serenLink=Join-Path ([Environment]::GetFolderPath('Startup')) 'SerenSystem.lnk'
if (Test-Path -LiteralPath $serenLink) { Remove-Item -LiteralPath $serenLink }
Write-Output 'Seren automatic login launch removed. Running applications remain open.'
