@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   REAL-TIME OPENCLOW STACK CHECK
echo ========================================================
echo.
echo WHY:
echo   Confirms backend + proxy + upstream OpenClaw are connected
echo   before running hardening demos.
echo.
echo WHAT THIS DOES:
echo   1) Runs guardianctl health/status checks.
echo   2) Verifies backend auth path with admin demo creds.
echo   3) Prints latest backend security event.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"

if not exist "%~dp0guardian\config\openclaw_realtime_demo.yaml" (
  echo [ERROR] Realtime config not found: guardian\config\openclaw_realtime_demo.yaml
  echo Run first: demo_realtime_openclaw_0_start_stack.bat
  exit /b 1
)

"%PYTHON_CMD%" "%~dp0guardianctl.py" status --config "%~dp0guardian\config\openclaw_realtime_demo.yaml"
if errorlevel 1 (
  echo.
  echo [WARN] One or more services are down.
  echo Keep stack running via demo_realtime_openclaw_0_start_stack.bat
)

echo.
echo [CHECK] Backend auth/compliance endpoint
curl.exe -s -u admin:admin-pass "http://127.0.0.1:8001/api/v1/compliance/report"
if errorlevel 1 (
  echo.
  echo [ERROR] Could not query backend compliance endpoint.
  exit /b 1
)

echo.
echo.
echo [CHECK] Latest backend event
curl.exe -s -u admin:admin-pass "http://127.0.0.1:8001/api/v1/events?limit=1"
echo.
echo.
echo [DONE] Realtime stack check completed.
pause
