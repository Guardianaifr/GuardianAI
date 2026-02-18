@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 8: TELEMETRY API KEY LIFECYCLE
echo ========================================================
echo.
echo WHY:
echo   Key lifecycle controls are required to limit blast
echo   radius and rotate credentials during incidents.
echo.
echo WHAT THIS DOES:
echo   1) Creates a managed API key.
echo   2) Lists keys as auditor (read-only role).
echo   3) Rotates the key material.
echo   4) Revokes the key.
echo.

python "%~dp0tools\hardening_demos.py" api-keys %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 8 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 8 completed.
pause
