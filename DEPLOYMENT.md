# GuardianAI Deployment Guide

This guide is aligned with the current repository behavior.

## Prerequisites

- Python 3.12 required (project standard)
- Docker (optional)
- Local upstream model/service endpoint (default: `http://127.0.0.1:8080`)

## Local Run (Python)

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure (optional):
- Default config: `guardian/config/config.yaml`
- Override with env var:
```bash
# Windows PowerShell
$env:GUARDIAN_CONFIG="guardian/config/config.yaml"
```

3. Start services:
```bash
python guardianctl.py setup
python guardianctl.py start
```

4. Verify health:
- Proxy: `http://127.0.0.1:8081/health`
- Backend: `http://127.0.0.1:8001/health`

## One-Click Customer Activation (All Features)

For buyer-ready launch with all controls activated and automatic secret generation:

```bash
python guardianctl.py one-click --target-url http://127.0.0.1:8080
```

Behavior:
- Generates missing runtime secrets:
  - `GUARDIAN_ADMIN_PASS`
  - `GUARDIAN_BACKEND_TOKEN`
  - `GUARDIAN_SERVICE_AUTH_TOKEN`
  - `GUARDIAN_ADMIN_BYPASS_TOKEN`
- Writes runtime config:
  - `guardian/config/one_click_runtime.yaml`
- Starts full stack:
  - Backend on `:8001`
  - Proxy on `:8081`
- Proxy serving defaults to `waitress` (`GUARDIAN_WSGI_SERVER=waitress`) for production-safe WSGI runtime.

If you only want config + secrets without starting services:

```bash
python guardianctl.py one-click --no-start
```

## Docker

Start with compose:
```bash
docker-compose up -d
```

If you expose services publicly:
- Put Guardian behind TLS reverse proxy.
- Do not expose upstream model endpoint directly.

## Runtime Ports (default)

- Upstream model/service: `127.0.0.1:8080`
- Guardian proxy: `127.0.0.1:8081`
- Backend API/dashboard: `127.0.0.1:8001`

## Production Checklist

- Change default admin credentials (`GUARDIAN_ADMIN_PASS`).
- **Financial Controls (Decision FL_008):** Slippage-setting via GuardianAI is explicitly unsupported and intentionally hard-blocked until a valid 1inch API key is provisioned in the configuration to allow dynamic depth verification.
- For multi-worker deployments (e.g. uvicorn with --workers > 1), use the `redis` rate limit backend (`GUARDIAN_RATE_LIMIT_BACKEND=redis`) to ensure rate limits are shared. The default `memory` backend enforces limits per-worker.
- Keep upstream service on localhost/private network only.
- Expose only Guardian ingress as needed.
- Enable host-level firewall and log rotation.
- Run `python -m pytest tests -q` before release.

## Current Validation Snapshot

- Tests: `61/61` passing (latest local validation)
- Runtime standard: use Python 3.12 for full compatibility.

## Related Docs

- `HARDENING.md`
- `OPERATIONS.md`
- `TROUBLESHOOTING.md`
- `README.md`
- `PRODUCTION_LAUNCH_RUNBOOK.md`


