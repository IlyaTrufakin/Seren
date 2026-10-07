@echo off
chcp 65001 > nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Python environment .venv is missing. Create it before testing.
    pause
    exit /b 1
)
.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -v
if errorlevel 1 goto failed
.venv\Scripts\python.exe -X utf8 scripts\replay_telegram.py %*
if errorlevel 1 goto failed
.venv\Scripts\python.exe -X utf8 scripts\evaluate_lead_time.py --decisions test_results\telegram_replay\decisions.csv
if errorlevel 1 goto failed
echo Test results: test_results\telegram_replay\REPORT.md
echo Evacuation timing: test_results\evacuation\REPORT.md
pause
exit /b 0
:failed
echo A test failed. Read the output above.
pause
exit /b 1
