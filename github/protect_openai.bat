@echo off
title GuardianAI - OpenAI Shield (Codex)
color 0A

echo ========================================================
echo   GuardianAI: OPENAI API SHIELD
echo ========================================================
echo.
echo [!] TARGET:   https://api.openai.com
echo [!] PORT:     8084
echo [!] FEATURES: PII Redaction, Injection Blocking
echo.
echo Configure your tools (Cursor, VSCode, Copilot wrappers) to use:
echo Base URL: http://localhost:8084/v1
echo.

set GUARDIAN_CONFIG=guardian/config/openai_config.yaml
python guardian/main.py

pause
