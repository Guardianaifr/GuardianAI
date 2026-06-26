@echo off
title GuardianAI Status Check
color 0E
cls

cd /d "%~dp0"

set PYTHON_CMD=.venv312\Scripts\python.exe
if not exist "%PYTHON_CMD%" set PYTHON_CMD=python

echo.
echo ========================================================
echo   GUARDIAN AI - STATUS CHECK
echo ========================================================
echo.

"%PYTHON_CMD%" guardianctl.py status
echo.
"%PYTHON_CMD%" guardianctl.py hardening-check --strict

echo.
pause
