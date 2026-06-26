@echo off
chcp 65001 > nul
setlocal

echo.
echo ========================================================
echo   HARDENING DEMO 0: START BACKEND (DEMO CONFIG)
echo ========================================================
echo.
echo WHY:
echo   We need a predictable backend environment so every demo
echo   has known users, passwords, and hardening behavior.
echo.
echo WHAT THIS DOES:
echo   1) Sets demo credentials for admin/auditor/user.
echo   2) Enables auth lockout controls.
echo   3) Starts backend API at http://127.0.0.1:8001
echo.
echo Keep this window open while running demo_hardening_1..9.
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

python "%~dp0backend\main.py"
