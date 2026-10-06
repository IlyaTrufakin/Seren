@echo off
chcp 65001 > nul
title TM221 Modbus Gateway (Watchdog Runner)
cd /d "%~dp0"

echo ========================================================
echo   TM221 Modbus TCP Gateway - Сторожевой режим (Watchdog)
echo   Автоматический перезапуск при сбоях и падениях
echo ========================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [ИНФО] Первичная настройка окружения .venv...
    python -m venv .venv
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)

:run_loop
echo [%date% %time%] Запуск шлюза Modbus TCP...
.venv\Scripts\python.exe main.py
set EXIT_CODE=%errorlevel%

echo [%date% %time%] Приложение завершило работу (код: %EXIT_CODE%).
if "%EXIT_CODE%"=="0" (
    echo [WATCHDOG] Приложение закрыто штатно (код 0).
    choice /c YN /t 5 /d Y /m "Перезапустить? Y - перезапуск, N - выход (автоперезапуск через 5 сек)"
    if errorlevel 2 exit /b 0
)

echo [WATCHDOG] Перезапуск через 3 секунды... (Ctrl+C для отмены)
ping -n 4 127.0.0.1 > nul
goto run_loop
