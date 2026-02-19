@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   REAL-TIME OPENCLOW DEMO 2: INJECTION BLOCK
echo ========================================================
echo.
echo WHY:
echo   Proves Guardian blocks malicious prompt-injection attempts
echo   before they reach your live OpenClaw endpoint.
echo.
echo WHAT THIS DOES:
echo   1) Sends a known malicious prompt via proxy.
echo   2) Expects HTTP 403 block decision from Guardian.
echo   3) Verifies backend telemetry records a blocked event.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"

"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" proxy-injection --base-url http://127.0.0.1:8001 --proxy-url http://127.0.0.1:8081 --model openclaw %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo failed.
  echo Ensure stack is running: demo_realtime_openclaw_0_start_stack.bat
  exit /b 1
)

echo.
echo [PASS] Real-time injection block demo completed.
pause
