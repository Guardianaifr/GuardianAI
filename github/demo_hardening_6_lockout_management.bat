@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 6: FAILED LOGIN LOCKOUT + CLEAR
echo ========================================================
echo.
echo WHY:
echo   This proves brute-force containment and operational
echo   recovery: lock suspicious sources, then clear safely.
echo.
echo WHAT THIS DOES:
echo   1) Generates repeated failed logins.
echo   2) Shows valid login is temporarily locked (HTTP 429).
echo   3) Auditor lists lockouts.
echo   4) Admin clears lockout and login works again.
echo.

python "%~dp0tools\hardening_demos.py" lockout %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 6 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 6 completed.
pause
