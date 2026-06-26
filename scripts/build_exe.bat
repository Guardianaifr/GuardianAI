@echo off
title GuardianAI Build Script
color 0F
cls

echo ========================================================
echo   GuardianAI - Executable Builder
echo   (Creates 'dist/GuardianAI' folder)
echo ========================================================
echo.

REM 1. Check for PyInstaller
pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] PyInstaller not found. Installing...
    pip install pyinstaller
)

REM 2. Clean previous build
if exist "dist" (
    echo [INFO] Cleaning 'dist' folder...
    rmdir /s /q "dist"
)
if exist "build" (
    echo [INFO] Cleaning 'build' folder...
    rmdir /s /q "build"
)

REM 3. Run PyInstaller
echo.
echo [BUILD] Starting PyInstaller (This may take a minute)...
echo.
pyinstaller guardian.spec --clean --noconfirm

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build Failed! Check the logs above.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   BUILD SUCCESSFUL!
echo ========================================================
echo.
echo   Executable located at: dist\GuardianAI\GuardianAI.exe
echo.
echo   To test run:
echo   cd dist\GuardianAI
echo   GuardianAI.exe
echo.
pause
