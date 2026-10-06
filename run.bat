@echo off
chcp 65001 > nul
title TM221 Modbus Gateway
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [ИНФО] Создание виртуального окружения .venv...
    python -m venv .venv
    echo [ИНФО] Установка зависимостей из requirements.txt...
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)

echo [ИНФО] Запуск приложения...
start "" .venv\Scripts\python.exe main.py
exit
