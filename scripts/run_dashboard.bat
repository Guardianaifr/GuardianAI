@echo off
title GuardianAI - SOC Dashboard
color 0F

echo.
echo ========================================================
echo   GUARDIAN AI - OPEN DASHBOARD
echo ========================================================
echo.
echo Dashboard URL: http://127.0.0.1:8001
echo.

cd /d "%~dp0"

if not exist ".venv312\Scripts\python.exe" (
  echo [INFO] First-run setup detected. Installing dependencies...
  powershell -ExecutionPolicy Bypass -File ".\install.ps1"
  if errorlevel 1 (
    echo [ERROR] Installation failed. Please run install.ps1 manually.
    pause
    exit /b 1
  )
)

set PYTHON_CMD=.venv312\Scripts\python.exe
if not exist "%PYTHON_CMD%" set PYTHON_CMD=python

:: Open browser only (safe even if backend is already running)
"%PYTHON_CMD%" guardianctl.py dashboard

:: Show current health state so demo operator knows if stack is up
"%PYTHON_CMD%" guardianctl.py status

echo.
echo If Backend is DOWN above, start stack with:
echo   %PYTHON_CMD% guardianctl.py start
echo.
pause
