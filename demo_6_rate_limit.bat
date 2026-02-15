@echo off
chcp 65001 > nul
echo.
echo ========================================================
echo   DEMO 6: RATE LIMITING (DoS PROTECTION)
echo ========================================================
echo.
echo Goal: Trigger the 60 req/minute Rate Limit.
echo.
echo Sending 70 rapid requests...
echo.

echo Launching Flood Attack Simulator...
echo.

python tools/demo_flooder.py

echo.
echo.
echo ========================================================
echo   THE HONEST TRUTH: WHAT THIS DEMO PROVES
echo ========================================================
echo.
echo ✅ PROVES:
echo   - Token-bucket rate limiting enforces throughput caps (60 req/min).
echo   - Protects upstream LLM from cost spikes and abuse.
echo.
echo ❌ DOES NOT PROVE:
echo   - Distributed Denial of Service (DDoS) mitigation.
echo   - (Requires network-layer protection like Cloudflare).
echo.
echo 🚧 ROADMAP:
echo   - v2.1: Per-User and Per-IP rate limits.
echo.
pause
echo --------------------------------------------------------
echo EXPECTED: First 60 requests = 200 OK (Allowed).
echo           Requests 61+ = 429 TOO MANY REQUESTS (Blocked).
echo --------------------------------------------------------
pause
