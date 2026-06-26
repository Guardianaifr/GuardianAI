# Basic Launch Manifest

This package contains only the files required for a basic public GitHub launch.

## Included
- Core runtime: `guardian/`
- Backend API/telemetry: `backend/`
- Test suite: `tests/`
- Core docs: README/API/DEPLOYMENT/HARDENING/OPERATIONS/TROUBLESHOOTING/SECURITY/ROADMAP
- Launch scripts: `guardianctl.py`, `start_guardian.*`, `install.*`
- Container and deps: `Dockerfile`, `docker-compose.yml`, `requirements.txt`

## Intentionally excluded
- `agents/` (internal planning/report artifacts)
- `tools/` (internal benchmark/dev utilities)
- `dashboard/` and `node_modules/` (frontend/dev dependency bulk)
- media/demo binaries and local artifacts
- extra packaging/dev artifacts not required for basic launch
