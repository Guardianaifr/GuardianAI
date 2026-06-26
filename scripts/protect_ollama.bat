@echo off
title GuardianAI - Ollama Shield Mode
color 0B

echo ========================================================
echo   GuardianAI: OLLAMA INFRASTRUCTURE SHIELD
echo ========================================================
echo.
echo [!] PROBLEM:  Exposed Ollama API (Port 11434)
echo [!] RISKS:    Free GPU mining, Data exfiltration, abuses.
echo.
echo [x] SOLUTION: GuardianAI Reverse Proxy (Port 8082)
echo     + Authentication (Token Required)
echo     + Rate Limiting (20 req/min)
echo     + Impact Firewall (Jailbreak Detection)
echo.
echo --------------------------------------------------------
echo Starting Shield on http://localhost:8082...
echo Forwarding to: http://127.0.0.1:11434 (Standard Ollama)
echo.

:: Set config env var to use the ollama config
set GUARDIAN_CONFIG=guardian/config/ollama_config.yaml

python guardian/main.py

pause
