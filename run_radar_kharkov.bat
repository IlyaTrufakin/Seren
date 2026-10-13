@echo off
cd /d "%~dp0"
start "" "%~dp0.venv\Scripts\pythonw.exe" -m src.system_supervisor --analyzer-only "%~dp0profiles\radar_kharkov"
