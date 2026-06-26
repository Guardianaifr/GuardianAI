@echo off
title GuardianAI Git Setup
color 0E
cls

echo ========================================================
echo   GuardianAI - Git Setup Wizard
echo   (Initializing Private Repository)
echo ========================================================
echo.

REM 1. Initialize Git if not present
if not exist ".git" (
    echo [INFO] Initializing new Git repository...
    git init
) else (
    echo [INFO] Git repository already exists.
)

REM 2. Configure Remote (Using your specific URL)
echo [INFO] Setting remote origin...
git remote remove origin >nul 2>&1
git remote add origin https://github.com/Guardianaifr/Guardian-private.git

REM 3. Stage & Commit
echo [INFO] Staging files...
git add .
echo [INFO] Committing changes...
git commit -m "Initial Release v1.0" >nul 2>&1

REM 4. Rename Branch
git branch -M main

REM 5. Push
echo.
echo ========================================================
echo   AUTHENTICATION REQUIRED
echo   A GitHub login window may pop up now.
echo   If asked for username/password:
echo     - Username: Guardianaifr
echo     - Password: Your GitHub Token (PAT) or Password
echo ========================================================
echo.
echo [INFO] Pushing to GitHub...
git push -u origin main

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Push Failed!
    echo.
    echo Possible Reasons:
    echo 1. You are not logged in.
    echo 2. The repository 'Guardian-private' does not exist on GitHub.
    echo 3. You created a Public repo but used a Private URL (or vice versa).
    echo.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Code pushed to GitHub!
pause
