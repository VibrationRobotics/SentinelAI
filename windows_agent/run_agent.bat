@echo off
:: Change to the directory where this batch file is located
:: This is required when running as Administrator
cd /d "%~dp0"

echo ============================================
echo   SentinelAI Windows Agent
echo ============================================
echo.

:: API Key Configuration (optional - get from dashboard Settings > API Keys)
:: Uncomment and set your API key for authenticated mode:
set SENTINEL_API_KEY=sk_live_YyOgBAAqHA0mSrsNS-wPcw0iQt47TPHqarCvsjRBxXs

:: Kill any existing agent processes to prevent duplicates
echo Stopping any existing agents...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq SentinelAI*" 2>nul
timeout /t 2 /nobreak >nul

:: Check if venv exists
if not exist "venv\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Installing dependencies...
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)

echo.
if defined SENTINEL_API_KEY (
    echo API Key: Configured
) else (
    echo API Key: Not configured (unauthenticated mode)
)
echo Starting agent... Press Ctrl+C to stop
echo.
python agent.py --dashboard http://148.170.66.162:8015
pause
