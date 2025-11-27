@echo off
echo ============================================
echo   SentinelAI Windows Agent Installer
echo ============================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Please run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [1/3] Installing Python dependencies...
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [2/3] Creating Windows Service (optional)...
echo Skipping service installation - run manually for now

echo.
echo [3/3] Installation complete!
echo.
echo ============================================
echo   To start the agent, run:
echo   python agent.py
echo.
echo   Or with custom dashboard URL:
echo   python agent.py --dashboard http://YOUR_IP:8015
echo ============================================
echo.
pause
