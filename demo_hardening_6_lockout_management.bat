@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 6: ACCOUNT LOCKOUT (BRUTE FORCE)
echo ========================================================
echo.
echo WHY:
echo   Prevent credential stuffing by locking accounts after N
echo   failed attempts.
echo.
echo WHAT THIS DOES:
echo   1) Sends 5 failed logins (Wrong Password).
echo   2) Sends 1 VALID login -> Expects 429 TOO MANY REQUESTS.
echo   3) Auditor lists lockouts.
echo   4) Admin clears lockout.
echo   5) Valid login succeeds.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" lockout %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 6 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 6 completed.
pause
