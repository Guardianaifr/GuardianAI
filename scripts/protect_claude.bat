@echo off
title GuardianAI - Claude Shield (Anthropic)
color 0D

echo ========================================================
echo   GuardianAI: CLAUDE API SHIELD
echo ========================================================
echo.
echo [!] TARGET:   https://api.anthropic.com
echo [!] PORT:     8083
echo [!] FEATURES: PII Redaction, Injection Blocking
echo.
echo Configure your tools (Cursor, VSCode) to use:
echo Base URL: http://localhost:8083
echo.

set GUARDIAN_CONFIG=guardian/config/claude_config.yaml
python guardian/main.py

pause
