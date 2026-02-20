@echo off
setlocal
chcp 65001 > nul
title GuardianAI - Enterprise Security Hardening Demo

:MENU
cls
echo.
echo ========================================================
echo   GUARDIAN AI - SECURITY HARDENING DEMOS
echo ========================================================
echo.
echo   [0] START STACK (Run this first!)
echo       (Starts Backend :8001 + Proxy :8081)
echo.
echo   --- IDENTITY ^& ACCESS ---
echo   [1] Posture Check
echo       (Health, Metrics, Compliance Report)
echo   [2] Identity ^& RBAC
echo       (Admin vs Auditor vs User Permissions)
echo   [3] Session Inventory
echo       (Admin tracking active user sessions)
echo.
echo   --- REVOCATION ^& CONTAINMENT ---
echo   [4] Revoke Self
echo       (User logging out their own session)
echo   [5] Revoke by JTI
echo       (Precise token revocation by ID)
echo   [6] Account Lockout
echo       (Brute-force protection trigger)
echo   [7] Admin Containment
echo       (Emergency "Lock User" / "Lock All")
echo.
echo   --- ADVANCED ---
echo   [8] API Key Lifecycle
echo       (Create, Rotate, Revoke API Keys)
echo   [9] Audit Integrity
echo       (Verify Immutable Ledger Chain)
echo.
echo   [Q] Quit
echo.
echo ========================================================
set /p choice=Select an option [0-9, Q]: 

if /i "%choice%"=="0" goto START_STACK
if /i "%choice%"=="1" goto DEMO_POSTURE
if /i "%choice%"=="2" goto DEMO_RBAC
if /i "%choice%"=="3" goto DEMO_SESSIONS
if /i "%choice%"=="4" goto DEMO_REVOKE
if /i "%choice%"=="5" goto DEMO_JTI
if /i "%choice%"=="6" goto DEMO_LOCKOUT
if /i "%choice%"=="7" goto DEMO_CONTAIN
if /i "%choice%"=="8" goto DEMO_API
if /i "%choice%"=="9" goto DEMO_AUDIT
if /i "%choice%"=="Q" goto END

echo Invalid choice.
pause
goto MENU

:START_STACK
echo.
echo Launching Stack in a new window...
start "Guardian Stack" cmd /k "%~dp0demo_realtime_openclaw_0_start_stack.bat"
echo.
echo [INFO] Please wait for the new window to report "Stack started".
echo.
pause
goto MENU

:DEMO_POSTURE
echo.
echo [Running Posture Check...]
call demo_hardening_1_posture.bat
pause
goto MENU

:DEMO_RBAC
echo.
echo [Running Identity & RBAC Demo...]
call demo_hardening_2_identity_rbac.bat
pause
goto MENU

:DEMO_SESSIONS
echo.
echo [Running Session Inventory Demo...]
call demo_hardening_3_session_inventory.bat
pause
goto MENU

:DEMO_REVOKE
echo.
echo [Running Revoke Self Demo...]
call demo_hardening_4_revoke_self.bat
pause
goto MENU

:DEMO_JTI
echo.
echo [Running Revoke by JTI Demo...]
call demo_hardening_5_revoke_self_jti.bat
pause
goto MENU

:DEMO_LOCKOUT
echo.
echo [Running Account Lockout Demo...]
call demo_hardening_6_lockout_management.bat
pause
goto MENU

:DEMO_CONTAIN
echo.
echo [Running Admin Containment Demo...]
call demo_hardening_7_admin_containment.bat
pause
goto MENU

:DEMO_API
echo.
echo [Running API Key Lifecycle Demo...]
call demo_hardening_8_api_key_lifecycle.bat
pause
goto MENU

:DEMO_AUDIT
echo.
echo [Running Audit Integrity Demo...]
call demo_hardening_9_audit_integrity.bat
pause
goto MENU

:END
endlocal
exit /b 0
