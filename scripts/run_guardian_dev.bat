@echo off
title GuardianAI Stack Launcher (Development Mode)
color 0A

echo ========================================================
echo   GUARDIAN AI - STARTING SERVICES IN DEV MODE
echo ========================================================
echo.
echo Launching local proxy and SOC API stack...
echo.

cd /d "%~dp0"

:: Disable license validation for local developer sessions
set GUARDIAN_LICENSE_ENFORCEMENT=false

set PYTHON_CMD=.venv312\Scripts\python.exe
if not exist "%PYTHON_CMD%" set PYTHON_CMD=python

"%PYTHON_CMD%" guardianctl.py start --allow-risky-ports

echo.
pause
