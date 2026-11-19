@echo off
setlocal enabledelayedexpansion
title Git-Vault Enterprise - Agent Guard
cd /d "%~dp0"

if "%1"=="--silent" goto DAEMON_MODE
if "%1"=="--daemon" goto DAEMON_MODE

echo =======================================================
echo   [GIT-VAULT] Enterprise - Agent Guard Starting...
echo =======================================================
echo.

netstat -ano | findstr "8765" | findstr "LISTENING" >nul 2>&1
if !errorlevel! equ 0 (
    echo [INFO] Port 8765 is already running. Opening browser...
    start "" "http://127.0.0.1:8765"
    echo [OK] Web Console: http://127.0.0.1:8765
    goto :eof
)

start "" "http://127.0.0.1:8765"

echo Starting Python local server at http://127.0.0.1:8765 ...
python server.py

pause
goto :eof

:DAEMON_MODE
if not exist "logs" mkdir "logs"
netstat -ano | findstr "8765" | findstr "LISTENING" >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Git-Vault server is already running in background (http://127.0.0.1:8765)
    goto :eof
)
echo [GIT-VAULT] Starting server in background daemon mode...
start /b python server.py > logs\server.log 2>&1
echo [OK] Service started in background: http://127.0.0.1:8765
goto :eof
