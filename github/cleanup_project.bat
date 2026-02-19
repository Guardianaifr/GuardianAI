@echo off
title GuardianAI Project Cleanup
color 0E
cls

echo ========================================================
echo   GuardianAI - Project Cleanup
echo   (Moving development files to _archive)
echo ========================================================
echo.

if not exist "_archive" (
    echo [INFO] Creating _archive folder...
    mkdir _archive
)

echo [INFO] Moving files...

REM --- 1. Python Scripts (Debug/Benchmarks/Tests) ---
move benchmark_*.py _archive\ >nul 2>&1
move debug_*.py _archive\ >nul 2>&1
move verify_*.py _archive\ >nul 2>&1
move test_*.bat _archive\ >nul 2>&1
move repro_hang.py _archive\ >nul 2>&1
move probe.py _archive\ >nul 2>&1
move run_output_tests.bat _archive\ >nul 2>&1
move run_real_llm.bat _archive\ >nul 2>&1
move run_tests.bat _archive\ >nul 2>&1
move run_agents.py _archive\ >nul 2>&1
move mock_openclaw_agent.py _archive\ >nul 2>&1
move real_llm_bridge.py _archive\ >nul 2>&1
move simulate_live_demo.py _archive\ >nul 2>&1
move check_pii.py _archive\ >nul 2>&1

REM --- 2. Documentation (Legacy) ---
move "ROADMAP.md" _archive\ >nul 2>&1
move "GuardianAI_PII_FP_PROBLEM.md" _archive\ >nul 2>&1
move "GuardianAI_Security_Benchmark_Report.md" _archive\ >nul 2>&1
move "GUARDIAN_AI_WHITEPAPER.md" _archive\ >nul 2>&1
move "EXPLAINER_SCRIPT.txt" _archive\ >nul 2>&1
move "DEPLOYMENT.md" _archive\ >nul 2>&1
move "API.md" _archive\ >nul 2>&1
move "HARDENING.md" _archive\ >nul 2>&1
move "OPERATIONS.md" _archive\ >nul 2>&1
move "TROUBLESHOOTING.md" _archive\ >nul 2>&1
move "GUARDIAN_AI_MASTER_GUIDE.md" _archive\ >nul 2>&1


REM --- 3. Logs & Data ---
move "sim_log.txt" _archive\ >nul 2>&1
move "sim_debug.txt" _archive\ >nul 2>&1
move "sweep_results.txt" _archive\ >nul 2>&1
move "benchmark_debug.log" _archive\ >nul 2>&1
move "test_ws.html" _archive\ >nul 2>&1
move "verify_*.bat" _archive\ >nul 2>&1


echo.
echo ========================================================
echo   CLEANUP COMPLETE!
echo   Check the '_archive' folder.
echo ========================================================
echo.
pause

