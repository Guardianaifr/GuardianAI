@echo off
title GuardianAI - Interactive Launcher
color 0B

echo.
echo      FAILED TO LOAD CONFIG?
echo      Run this wizard to re-configure!
echo.

python guardian/wizard.py
pause
