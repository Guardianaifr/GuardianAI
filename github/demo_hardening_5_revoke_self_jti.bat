@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 5: TARGETED SELF REVOKE BY JTI
echo ========================================================
echo.
echo WHY:
echo   Users need precise containment to kill only one stolen
echo   token while keeping their current session active.
echo.
echo WHAT THIS DOES:
echo   1) Creates user and auditor JWTs.
echo   2) Tries invalid operations:
echo      - revoke current token via self-jti (blocked)
echo      - revoke other user's token (blocked)
echo   3) Revokes one owned non-current JTI successfully.
echo.

python "%~dp0tools\hardening_demos.py" revoke-self-jti %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 5 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 5 completed.
pause
