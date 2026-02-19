@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   REAL-TIME OPENCLOW DEMO 1: SAFE TRAFFIC ALLOW
echo ========================================================
echo.
echo WHY:
echo   Proves Guardian passes benign user prompts to your live
echo   OpenClaw while still recording backend telemetry.
echo.
echo WHAT THIS DOES:
echo   1) Sends a safe chat prompt via Guardian proxy (8081).
echo   2) Expects HTTP 200 from live upstream path.
echo   3) Verifies backend telemetry contains allowed_request.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"

"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" proxy-safe --base-url http://127.0.0.1:8001 --proxy-url http://127.0.0.1:8081 --model openclaw %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo failed.
  echo Ensure stack is running: demo_realtime_openclaw_0_start_stack.bat
  exit /b 1
)

echo.
echo [PASS] Real-time safe traffic demo completed.
pause
