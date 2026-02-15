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

python guardian/runtime/interceptor.py
pause
