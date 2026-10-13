@echo off
cd /d "%~dp0"
start "" "%~dp0.venv\Scripts\pythonw.exe" -m src.channel_debugger --profile "%~dp0profiles\radar_kharkov" --archives "%~dp0logs\telegram_radar_kharkov_2026-10-12_2026-10-12_snapshot_213150.jsonl" --start 2026-10-12 --end 2026-10-12 --analyze
