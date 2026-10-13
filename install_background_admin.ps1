$ErrorActionPreference='Stop'
$serenResult=Join-Path $PSScriptRoot 'runtime\background_install_result.json'
try { & (Join-Path $PSScriptRoot 'install_background.ps1') }
catch {
    [IO.File]::WriteAllText($serenResult,(@{installed=$false;error=$_.Exception.Message} | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    exit 1
}
