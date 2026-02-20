@echo off
setlocal enabledelayedexpansion
title GuardianAI All-In-One Automated Test Suite
color 0B
cls

echo ========================================================
echo   GUARDIAN AI - UNIFIED AUTOMATION SUITE
echo   Executing all 15 Validation and Hardening Demos
echo ========================================================
echo.

set PYTHONIOENCODING=utf-8
set "PYTHON_CMD=.venv312\Scripts\python.exe"
if not exist "%PYTHON_CMD%" set "PYTHON_CMD=python"

echo [TEARDOWN] Ensuring clean port state (8001 / 8081)...
taskkill /f /im uvicorn.exe >nul 2>&1
taskkill /f /im python.exe /fi "WINDOWTITLE eq Guardian*" >nul 2>&1
%PYTHON_CMD% tools\manage_ports.py >nul 2>&1
echo [TEARDOWN] Database reset...
if exist "guardian.db" del "guardian.db"
echo.

set "GUARDIAN_ADMIN_USER=admin"
set "GUARDIAN_ADMIN_PASS=admin-pass"
set "GUARDIAN_AUDITOR_USER=auditor"
set "GUARDIAN_AUDITOR_PASS=auditor-pass"
set "GUARDIAN_USER_USER=user1"
set "GUARDIAN_USER_PASS=user-pass"
set "GUARDIAN_JWT_SECRET=demo-super-secret-change-me"
set "GUARDIAN_AUTH_LOCKOUT_ENABLED=true"
set "GUARDIAN_AUTH_LOCKOUT_MAX_ATTEMPTS=5"
set "GUARDIAN_AUTH_LOCKOUT_DURATION_SEC=60"

echo [STARTUP] Booting Guardian Backend and Proxy in the background...

:: Create a dynamic VBS launcher that executes Python directly without losing the environment
echo Set WshShell = CreateObject("WScript.Shell") > launch_silent.vbs
echo Set WshEnv = WshShell.Environment("PROCESS") >> launch_silent.vbs
echo WshEnv("GUARDIAN_ADMIN_USER") = "admin" >> launch_silent.vbs
echo WshEnv("GUARDIAN_ADMIN_PASS") = "admin-pass" >> launch_silent.vbs
echo WshEnv("GUARDIAN_AUDITOR_USER") = "auditor" >> launch_silent.vbs
echo WshEnv("GUARDIAN_AUDITOR_PASS") = "auditor-pass" >> launch_silent.vbs
echo WshEnv("GUARDIAN_USER_USER") = "user1" >> launch_silent.vbs
echo WshEnv("GUARDIAN_USER_PASS") = "user-pass" >> launch_silent.vbs
echo WshEnv("GUARDIAN_JWT_SECRET") = "demo-super-secret-change-me" >> launch_silent.vbs
echo WshEnv("GUARDIAN_AUTH_LOCKOUT_ENABLED") = "true" >> launch_silent.vbs
echo WshEnv("GUARDIAN_AUTH_LOCKOUT_MAX_ATTEMPTS") = "5" >> launch_silent.vbs
echo WshEnv("GUARDIAN_AUTH_LOCKOUT_DURATION_SEC") = "60" >> launch_silent.vbs
echo WshShell.Run "cmd /c .venv312\Scripts\python.exe guardianctl.py start", 0, False >> launch_silent.vbs

cscript //nologo launch_silent.vbs
echo Waiting for the proxy server to initialize (this can take up to 20s for the AI models)...

set MAX_RETRIES=20
set RETRY_COUNT=0
:wait_loop
%SystemRoot%\System32\curl.exe -s http://127.0.0.1:8081/health >nul 2>&1
if "%errorlevel%"=="0" goto server_ready

set /a RETRY_COUNT+=1
if %RETRY_COUNT% GEQ %MAX_RETRIES% (
    echo [ERROR] The Proxy failed to start within the expected timeframe.
    exit /b 1
)
ping 127.0.0.1 -n 2 >nul
goto wait_loop

:server_ready
echo.
echo [PASS] Proxy server is UP and ready on port 8081!
echo.

echo ========================================================
echo  PHASE 1: PROXY VULNERABILITY VALIDATIONS (6 Scenarios)
echo ========================================================
echo.

echo [1/15] Running Safe Allow Demo...
call demo_1_safe.bat --no-pause
echo.

echo [2/15] Running Injection Block Demo...
call demo_2_injection.bat --no-pause
echo.

echo [3/15] Running PII Redaction Demo...
call demo_3_pii.bat --no-pause
echo.

echo [4/15] Running Admin Authorization Bypass Demo...
call demo_4_admin_bypass.bat --no-pause
echo.

echo [5/15] Running Rogue Process (calc.exe) Sandbox Test...
start calc.exe
ping 127.0.0.1 -n 4 >nul
tasklist | findstr calc.exe >nul
if %errorlevel% equ 0 (
    echo [ERROR] calc.exe survived (Monitor malfunctioned)
) else (
    echo [PASS] calc.exe was violently terminated by the Monitor.
)
echo.

echo [6/15] Running DoS Rate Limiter Test Suite...
%PYTHON_CMD% tools\demo_flooder_oc.py
echo.

echo ========================================================
echo  PHASE 2: BACKEND HARDENING CONTROLS (9 Scenarios)
echo ========================================================
echo.

echo [7/15] Running Configuration Posture Demo...
%PYTHON_CMD% tools\hardening_demos.py posture --base-url http://127.0.0.1:8001
echo.

echo [8/15] Running Identity and RBAC Boundary Demo...
%PYTHON_CMD% tools\hardening_demos.py identity-rbac --base-url http://127.0.0.1:8001
echo.

echo [9/15] Running Session Inventory Segmentation Demo...
%PYTHON_CMD% tools\hardening_demos.py session-inventory --base-url http://127.0.0.1:8001
echo.

echo [10/15] Running Session Revocation (Self) Demo...
%PYTHON_CMD% tools\hardening_demos.py revoke-self --base-url http://127.0.0.1:8001
echo.

echo [11/15] Running Targeted Revocation (JTI) Demo...
%PYTHON_CMD% tools\hardening_demos.py revoke-self-jti --base-url http://127.0.0.1:8001
echo.

echo [12/15] Running Brute Force Lockout Management Demo...
%PYTHON_CMD% tools\hardening_demos.py lockout --base-url http://127.0.0.1:8001
echo.

echo [13/15] Running Global Admin Containment Demo...
%PYTHON_CMD% tools\hardening_demos.py admin-containment --base-url http://127.0.0.1:8001
echo.

echo [14/15] Running API Key Lifecycle Automation Demo...
%PYTHON_CMD% tools\hardening_demos.py api-keys --base-url http://127.0.0.1:8001
echo.

echo [15/15] Running Immutable Audit Integrity Trace Demo...
%PYTHON_CMD% tools\hardening_demos.py audit --base-url http://127.0.0.1:8001
echo.

echo ========================================================
echo   ALL 15 VALIDATION DEMOS COMPLETED SUCCESSFULLY.
echo ========================================================
echo [CLEANUP] Tearing down test backend...
taskkill /f /im uvicorn.exe >nul 2>&1
%PYTHON_CMD% tools\manage_ports.py >nul 2>&1
if exist "guardian.db" del "guardian.db"
echo.

pause
