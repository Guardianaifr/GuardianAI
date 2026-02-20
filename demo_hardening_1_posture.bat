@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 1: SECURITY POSTURE CHECKS
echo ========================================================
echo.
echo WHY:
echo   This proves the platform exposes operational visibility
echo   before incident response: health, metrics, compliance,
echo   and RBAC policy transparency.
echo.
echo WHAT THIS DOES:
echo   1) Calls /health and /metrics.
echo   2) Reads /api/v1/compliance/report.
echo   3) Reads /api/v1/rbac/policy as auditor.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" posture %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 1 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 1 completed.
pause
