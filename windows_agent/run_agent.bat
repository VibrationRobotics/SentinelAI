@echo off
echo ============================================
echo   SentinelAI Windows Agent
echo ============================================
echo.

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
echo Starting agent... Press Ctrl+C to stop
echo.
python agent.py --dashboard http://localhost:8015
pause
