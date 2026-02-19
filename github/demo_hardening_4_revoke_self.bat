@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 4: USER SELF-CONTAINMENT
echo ========================================================
echo.
echo WHY:
echo   A user should be able to contain their own compromise
echo   without admin intervention by logging out other devices.
echo.
echo WHAT THIS DOES:
echo   1) Creates two user JWTs.
echo   2) Calls /api/v1/auth/sessions/revoke-self with
echo      exclude_current=true.
echo   3) Confirms current token still works while the other
echo      token is revoked.
echo.

python "%~dp0tools\hardening_demos.py" revoke-self %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 4 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 4 completed.
pause
