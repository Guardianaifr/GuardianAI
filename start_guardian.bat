@echo off
title GuardianAI Launcher
color 0F
cls

echo.
echo ========================================================
echo   GuardianAI - Unified Launcher
echo   (Protecting OpenClaw since 2026)
echo ========================================================
echo.
echo [1] START SHIELD (Load last config)
echo [2] CONFIG WIZARD (Setup new shield)
echo [3] LAUNCH DASHBOARD (View telemetry)
echo [4] EXIT
echo.

set /p choice="Select option [1-4]: "

if "%choice%"=="1" goto start_shield
if "%choice%"=="2" goto wizard
if "%choice%"=="3" goto dashboard
if "%choice%"=="4" goto end

:start_shield
cls
if not exist "guardian\config\wizard_config.yaml" goto no_config
echo Starting GuardianAI with last known config...
set GUARDIAN_CONFIG=guardian\config\wizard_config.yaml
python guardian\main.py
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
python guardian\wizard.py
goto end

:dashboard
cls
call run_dashboard.bat
goto end

:end
exit /b
