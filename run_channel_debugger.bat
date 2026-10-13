@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  python -m venv .venv
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)
".venv\Scripts\python.exe" -c "from zoneinfo import ZoneInfo; ZoneInfo('Europe/Kyiv')" >nul 2>&1
if errorlevel 1 ".venv\Scripts\python.exe" -m pip install tzdata==2026.5
".venv\Scripts\python.exe" -m src.channel_debugger %*
if errorlevel 1 pause
