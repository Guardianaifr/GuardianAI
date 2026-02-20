@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 9: AUDIT INTEGRITY + DELIVERY OPS
echo ========================================================
echo.
echo WHY:
echo   Security events are useful only if logs are tamper-
echo   evident and failed external deliveries are manageable.
echo.
echo WHAT THIS DOES:
echo   1) Verifies hash-chain integrity.
echo   2) Reads audit summary health signals.
echo   3) Lists failed deliveries.
echo   4) Retries queued failures.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" audit %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 9 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 9 completed.
pause
