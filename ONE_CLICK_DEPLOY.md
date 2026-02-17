# One-Click Launch (Windows, macOS, Linux)

GuardianAI now includes a cross-platform control script: `guardianctl.py`.

## One-Command Install

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

```bash
# macOS / Linux
./install.sh
```

Installer options:

- Windows:
  - `-SkipNode`
  - `-SkipPythonInstall`
  - `-RunSetup`
  - `-RunStart`
- macOS/Linux:
  - `--skip-node`
  - `--run-setup`
  - `--run-start`

## Commands

```bash
# Setup a new shield profile (interactive wizard)
.venv312/Scripts/python.exe guardianctl.py setup

# Start backend + Guardian proxy
.venv312/Scripts/python.exe guardianctl.py start

# Check status of upstream/proxy/backend/dashboard
.venv312/Scripts/python.exe guardianctl.py status

# Security hardening precheck (fails in strict mode if risky ports are public)
.venv312/Scripts/python.exe guardianctl.py hardening-check --strict

# Open dashboard in your browser
.venv312/Scripts/python.exe guardianctl.py dashboard
```

## Platform launchers

- Windows: `start_guardian.bat`
- macOS/Linux: `./start_guardian.sh`
- Windows quick helpers: `run_dashboard.bat`, `check_status.bat`

Both launchers perform first-run installation automatically if no virtual environment exists.

## Notes

- `start` uses `guardian/config/wizard_config.yaml` if present, otherwise `guardian/config/config.yaml`.
- Dashboard URL: `http://127.0.0.1:8001`
- Proxy URL: `http://127.0.0.1:8081`
- Default dashboard credentials are for local demo only; set:
  - `GUARDIAN_ADMIN_USER`
  - `GUARDIAN_ADMIN_PASS`
