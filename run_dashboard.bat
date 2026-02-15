@echo off
title GuardianAI - SOC Dashboard
color 0F

echo.
echo ========================================================
echo   STARTING GUARDIAN AI SOC DASHBOARD
echo ========================================================
echo.
echo Access the Dashboard at: http://localhost:8001
echo.

:: Ensure we are in the project root
cd /d "%~dp0"

:: Check if backend folder exists
if not exist "backend\main.py" (
    echo [ERROR] backend/main.py not found!
    echo Current Dir: %CD%
    pause
    exit /b
)

python backend/main.py
pause
