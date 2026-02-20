@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 2: IDENTITY + RBAC VISIBILITY
echo ========================================================
echo.
echo WHY:
echo   We need evidence that each role receives the correct
echo   permission scope, which is critical for least privilege.
echo.
echo WHAT THIS DOES:
echo   1) Issues JWTs for admin, auditor, and user.
echo   2) Calls /api/v1/auth/whoami for each role.
echo   3) Prints role and permission counts.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" identity-rbac %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 2 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 2 completed.
pause
