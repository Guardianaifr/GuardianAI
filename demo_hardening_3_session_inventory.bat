@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 3: SESSION INVENTORY CONTROL
echo ========================================================
echo.
echo WHY:
echo   Incident response requires visibility into active JWT
echo   sessions and strong role boundaries on that visibility.
echo.
echo WHAT THIS DOES:
echo   1) Creates a user session.
echo   2) Auditor lists sessions from /api/v1/auth/sessions.
echo   3) Verifies user role is blocked from that endpoint.
echo.

python "%~dp0tools\hardening_demos.py" session-inventory %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 3 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 3 completed.
pause
