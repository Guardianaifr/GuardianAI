@echo off
title GuardianAI Proxy
color 0A

echo.
echo ========================================================
echo   STARTING GUARDIAN PROXY (INTERCEPTOR)
echo ========================================================
echo.

:: Add 'guardian' directory to PYTHONPATH to fix imports
set PYTHONPATH=%CD%\guardian;%CD%

set PYTHON_CMD=.venv312\Scripts\python.exe
if not exist "%PYTHON_CMD%" set PYTHON_CMD=python

%PYTHON_CMD% guardian/runtime/interceptor.py
pause
