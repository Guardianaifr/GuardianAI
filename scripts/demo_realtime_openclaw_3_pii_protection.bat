@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   REAL-TIME OPENCLOW DEMO 3: PII / LEAK PROTECTION
echo ========================================================
echo.
echo WHY:
echo   Proves live output protection is active when OpenClaw
echo   is asked for sensitive information.
echo.
echo WHAT THIS DOES:
echo   1) Sends a high-risk leak prompt via proxy.
echo   2) Checks response path for redaction behavior.
echo   3) Verifies backend telemetry logs data leak/redaction.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"

"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" proxy-pii --base-url http://127.0.0.1:8001 --proxy-url http://127.0.0.1:8081 --model openclaw %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo failed.
  echo Ensure stack is running: demo_realtime_openclaw_0_start_stack.bat
  exit /b 1
)

echo.
echo [PASS] Real-time PII protection demo completed.
pause
