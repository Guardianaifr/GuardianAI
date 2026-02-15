@echo off
chcp 65001 > nul
echo.
echo ========================================================
echo   DEMO 1: SAFE REQUEST (BASELINE)
echo ========================================================
echo.
echo Goal: Verify that normal traffic passes through GuardianAI.
echo.
echo Sending: "Hello, are you online?"
echo.

curl -X POST http://localhost:8081/v1/chat/completions ^
  -H "Content-Type: application/json" ^
  -H "Authorization: Bearer 5a98a95f112930867b69e20d1b7495edc51ef6f7931a9175" ^
  -d "{\"model\": \"openclaw\", \"messages\": [{\"role\": \"user\", \"content\": \"Hello, are you online?\"}]}"

echo.
echo.
echo --------------------------------------------------------
echo EXPECTED: HTTP 200 OK (Response from OpenClaw)
echo --------------------------------------------------------
pause
