@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 4: SELF-REVOCATION (LOGOUT)
echo ========================================================
echo.
echo WHY:
echo   Users must be able to terminate their own sessions (logout)
echo   or revoke other active sessions (device management).
echo.
echo WHAT THIS DOES:
echo   1) Creates 2 sessions for User1.
echo   2) Calls /revoke-self to kill all OTHER sessions.
echo   3) Verifies current token works, other token fails (401).
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" revoke-self %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 4 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 4 completed.
pause
