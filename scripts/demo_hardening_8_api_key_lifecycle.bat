@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 8: API KEY LIFECYCLE
echo ========================================================
echo.
echo WHY:
echo   Service accounts need API keys, but they must be
echo   rotatable and revocable.
echo.
echo WHAT THIS DOES:
echo   1) Admin creates a new API Key.
echo   2) Auditor lists keys.
echo   3) Admin rotates the key (new secret, same ID).
echo   4) Admin revokes the key.
echo.

set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"
"%PYTHON_CMD%" "%~dp0tools\hardening_demos.py" api-keys %*
if errorlevel 1 (
  echo.
  echo [FAIL] Demo 8 failed.
  echo Ensure backend is running: demo_hardening_0_start_backend.bat
  exit /b 1
)

echo.
echo [PASS] Demo 8 completed.
pause
