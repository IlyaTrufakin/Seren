@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Right-click this file and choose Run as administrator.'; exit 1 }; & '%~dp0install_background_admin.ps1'"
if errorlevel 1 (echo Background installation was not completed.) else (echo Background startup installed. Production starts on the next reboot.)
pause
