@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   REAL-TIME OPENCLOW DEMO 0: START LIVE STACK
echo ========================================================
echo.
echo WHY:
echo   To run real-time demos against your own OpenClaw, we need
echo   Guardian proxy + backend telemetry running together.
echo.
echo WHAT THIS DOES:
echo   1) Builds a demo config targeting your OpenClaw URL.
echo   2) Optionally sets an upstream bearer key for OpenClaw.
echo   3) Starts backend (8001) and Guardian proxy (8081).
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"

set "OPENCLAW_URL="
set /p OPENCLAW_URL="Enter OpenClaw base URL [http://127.0.0.1:8080]: "
if "%OPENCLAW_URL%"=="" set "OPENCLAW_URL=http://127.0.0.1:8080"

set "OPENCLAW_KEY="
set /p OPENCLAW_KEY="Optional OpenClaw bearer key (leave blank if none): "

"%PYTHON_CMD%" "%~dp0tools\setup_openclaw_realtime_demo.py" --target-url "%OPENCLAW_URL%" --upstream-key "%OPENCLAW_KEY%"
if errorlevel 1 (
  echo.
  echo [ERROR] Failed to prepare real-time demo config.
  exit /b 1
)

set "GUARDIAN_ADMIN_USER=admin"
set "GUARDIAN_ADMIN_PASS=guardian26"
set "GUARDIAN_AUDITOR_USER=auditor"
set "GUARDIAN_AUDITOR_PASS=auditor-pass"
set "GUARDIAN_USER_USER=user1"
set "GUARDIAN_USER_PASS=user-pass"
set "GUARDIAN_JWT_SECRET=demo-super-secret-change-me"
set "GUARDIAN_AUTH_LOCKOUT_ENABLED=true"
set "GUARDIAN_AUTH_LOCKOUT_MAX_ATTEMPTS=5"
set "GUARDIAN_AUTH_LOCKOUT_DURATION_SEC=60"

echo.
echo Starting stack with config: guardian\config\openclaw_realtime_demo.yaml
echo Keep this window open while running demo_realtime_openclaw_1..3.
echo.
"%PYTHON_CMD%" "%~dp0guardianctl.py" start --config "%~dp0guardian\config\openclaw_realtime_demo.yaml"
