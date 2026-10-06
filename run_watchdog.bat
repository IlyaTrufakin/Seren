@echo off
chcp 65001 > nul
title TM221 Modbus Gateway (Watchdog Runner)
cd /d "%~dp0"

echo ========================================================
echo   TM221 Modbus TCP Gateway - Сторожевой режим (Watchdog)
echo   Автоматический перезапуск при любых сбоях и падениях
echo ========================================================
echo.

:check_env
if not exist ".venv\Scripts\python.exe" (
    echo [ИНФО] Первичная настройка окружения .venv...
    python -m venv .venv
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)

:run_loop
echo [%date% %time%] Запуск шлюза Modbus TCP...
.venv\Scripts\python.exe main.py
set EXIT_CODE=%errorlevel%

echo [%date% %time%] Приложение завершило работу (код возврата: %EXIT_CODE%).
echo [WATCHDOG] Перезапуск приложения через 3 секунды...
timeout /t 3 /nobreak > nul
goto run_loop
