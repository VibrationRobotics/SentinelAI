@echo off
title SentinelAI Desktop Launcher
color 0A

echo.
echo  ╔═══════════════════════════════════════════════════════════╗
echo  ║           SentinelAI Desktop Launcher                     ║
echo  ║     Starting Agent and GUI...                             ║
echo  ╚═══════════════════════════════════════════════════════════╝
echo.

:: Configuration
set DASHBOARD_URL=http://localhost:8015
set AGENT_PATH=%~dp0..\windows_agent\agent.py

:: Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

:: Check if agent exists
if not exist "%AGENT_PATH%" (
    echo [ERROR] Agent not found at: %AGENT_PATH%
    pause
    exit /b 1
)

:: Start the agent in background
echo [INFO] Starting SentinelAI Agent...
start /B python "%AGENT_PATH%" --dashboard %DASHBOARD_URL%

:: Wait a moment for agent to start
timeout /t 2 /nobreak >nul

:: Check if Tauri exe exists
if exist "%~dp0src-tauri\target\release\sentinel-desktop.exe" (
    echo [INFO] Starting SentinelAI Desktop GUI...
    start "" "%~dp0src-tauri\target\release\sentinel-desktop.exe"
) else if exist "%~dp0SentinelAI-Desktop.exe" (
    echo [INFO] Starting SentinelAI Desktop GUI...
    start "" "%~dp0SentinelAI-Desktop.exe"
) else (
    echo [INFO] GUI not built yet. Opening dashboard in browser...
    start "" "%DASHBOARD_URL%"
)

echo.
echo [SUCCESS] SentinelAI is running!
echo [INFO] Dashboard: %DASHBOARD_URL%
echo [INFO] Press any key to stop the agent...
pause >nul

:: Kill the agent when user presses a key
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *agent*" >nul 2>&1
echo [INFO] Agent stopped.
