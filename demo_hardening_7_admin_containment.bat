@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 7: ADMIN CONTAINMENT (PANIC BUTTON)
echo ========================================================
echo.
echo WHY:
echo   In a breach, manual intervention is required to stop
echo   an account (or everyone) immediately.
echo.
echo WHAT THIS DOES:
echo   1) Admin calls /revoke-user (containing User1).
echo   2) Admin calls /revoke-all (global logout, excluding admins).
echo   3) Verifies tokens are dead immediately.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" admin-containment %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 7 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 7 completed.
pause
