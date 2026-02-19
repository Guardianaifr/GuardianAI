@echo off
title GuardianAI Launcher
color 0F
cls

if not exist ".venv312\Scripts\python.exe" (
  echo.
  echo [INFO] First-run setup detected. Installing dependencies...
  powershell -ExecutionPolicy Bypass -File ".\install.ps1"
  if errorlevel 1 (
    echo.
    echo [ERROR] Installation failed. Please run install.ps1 manually.
    pause
    exit /b 1
  )
)

set PYTHON_CMD=.venv312\Scripts\python.exe
if not exist "%PYTHON_CMD%" set PYTHON_CMD=python

echo.
echo ========================================================
echo   GuardianAI - Unified Launcher
echo   (Protecting OpenClaw)
echo ========================================================
echo.
echo [1] START SHIELD (Load last config)
echo [2] CONFIG WIZARD (Setup new shield)
echo [3] LAUNCH DASHBOARD (View telemetry)
echo [4] STATUS CHECK (All services)
echo [5] REALTIME OPENCLOW STACK (Backend + Proxy)
echo [6] REALTIME STACK CHECK (Health + Auth + Events)
echo [7] EXIT
echo.

set /p choice="Select option [1-7]: "

if "%choice%"=="1" goto start_shield
if "%choice%"=="2" goto wizard
if "%choice%"=="3" goto dashboard
if "%choice%"=="4" goto status
if "%choice%"=="5" goto realtime_stack
if "%choice%"=="6" goto realtime_check
if "%choice%"=="7" goto end

:start_shield
cls
echo Starting GuardianAI stack...
"%PYTHON_CMD%" guardianctl.py start
goto end

:no_config
echo.
echo [ERROR] No configuration found!
echo Please run the Wizard first (Option 2).
echo.
pause
goto start_shield

:wizard
cls
"%PYTHON_CMD%" guardianctl.py setup
goto end

:dashboard
cls
"%PYTHON_CMD%" guardianctl.py dashboard
goto end

:status
cls
"%PYTHON_CMD%" guardianctl.py status
pause
goto end

:realtime_stack
cls
call demo_realtime_openclaw_0_start_stack.bat
goto end

:realtime_check
cls
call demo_realtime_openclaw_check.bat
goto end

:end
exit /b

