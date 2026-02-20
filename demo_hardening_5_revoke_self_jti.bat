@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 5: REVOKE BY JTI (SURGICAL)
echo ========================================================
echo.
echo WHY:
echo   If a specific device is stolen, we must revoke ONLY that
echo   token (via JTI) without logging the user out everywhere.
echo.
echo WHAT THIS DOES:
echo   1) Creates 3 tokens (Current, Stolen, Auditor).
echo   2) Tries to revoke Current (Fail - Safety Check).
echo   3) Tries to revoke Auditor (Fail - Tenant Isolation).
echo   4) Revokes Stolen JTI (Success).
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" revoke-self-jti %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 5 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 5 completed.
pause
