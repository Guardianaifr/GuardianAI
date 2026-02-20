@echo off
chcp 65001 > nul
echo.
echo ========================================================
echo   DEMO 5: ROGUE PROCESS DETECTION
echo ========================================================
echo.
echo Goal: Verify that GuardianAI detects AND TERMINATES malicious processes.
echo.
echo We have configured GuardianAI to block "calc.exe" (and UWP variants)
echo as a safe simulator for "nc.exe" (Netcat Hacker Tool).
echo.
echo.
echo 🛡️  GUARDIAN BLOCKLIST CONFIGURATION:
echo    - nc.exe (Netcat)
echo    - ncat.exe
echo    - netcat.exe
echo    - powershell.exe (Restricted)
echo    - cmd.exe (Restricted)
echo    - psexec.exe
echo.
echo Launching 'calc.exe' (Simulating a rogue tool)...
echo.
start calc.exe

echo Process launched. Waiting for GuardianAI to terminate it...
timeout /t 5

echo.
echo Watch it closely - GuardianAI should KILL it within 2-5 seconds.
echo.
echo --------------------------------------------------------
echo EXPECTED in Guardian Console:
echo "🛡️ HIGH ALERT: System Shield blocking rogue process... Terminated"
echo --------------------------------------------------------
echo.
echo ========================================================
echo   THE HONEST TRUTH: WHAT THIS DEMO PROVES
echo ========================================================
echo.
echo ✅ PROVES:
echo   - Guardian monitors and kills explicitly blacklisted processes.
echo   - Reduces dwell time for known malicious tools.
echo.
pause
