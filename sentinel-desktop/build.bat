@echo off
echo ========================================
echo   SentinelAI Desktop - Build Script
echo ========================================
echo.

:: Check for Node.js
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Node.js not found. Please install Node.js 18+
    pause
    exit /b 1
)

:: Check for Cargo/Rust
where cargo >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Rust not found. Please install Rust via rustup
    pause
    exit /b 1
)

echo [1/4] Installing npm dependencies...
call npm install
if %ERRORLEVEL% neq 0 (
    echo ERROR: npm install failed
    pause
    exit /b 1
)

echo.
echo [2/4] Installing Tauri CLI...
call npm install -D @tauri-apps/cli@latest
if %ERRORLEVEL% neq 0 (
    echo ERROR: Tauri CLI install failed
    pause
    exit /b 1
)

echo.
echo [3/4] Creating icons directory...
if not exist "src-tauri\icons" mkdir src-tauri\icons

:: Create a simple placeholder icon (you should replace with real icons)
echo Creating placeholder icons...

echo.
echo [4/4] Building Tauri application...
call npm run tauri build
if %ERRORLEVEL% neq 0 (
    echo ERROR: Tauri build failed
    echo.
    echo Make sure you have:
    echo   - Visual Studio Build Tools installed
    echo   - WebView2 runtime installed
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo Output files:
echo   - src-tauri\target\release\SentinelAI Desktop.exe
echo   - src-tauri\target\release\bundle\msi\*.msi
echo   - src-tauri\target\release\bundle\nsis\*.exe
echo.
pause
