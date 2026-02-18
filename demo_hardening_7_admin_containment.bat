@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 7: ADMIN INCIDENT CONTAINMENT
echo ========================================================
echo.
echo WHY:
echo   During active incidents, admins need fast controls to
echo   revoke one user or many users without waiting for TTL.
echo.
echo WHAT THIS DOES:
echo   1) Uses /api/v1/auth/sessions/revoke-user.
echo   2) Uses /api/v1/auth/sessions/revoke-all with
echo      exclude_self=true.
echo   3) Confirms admin session survives while others are
echo      contained.
echo.

python "%~dp0tools\hardening_demos.py" admin-containment %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 7 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 7 completed.
pause
