# GuardianAI Deployment Guide

This guide is aligned with the current repository behavior.

## Prerequisites

- Python 3.12 required (project standard)
- Docker
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
- Run `.\.venv312\Scripts\pytest.exe tests -q` before release.

## Current Validation Snapshot

- Tests: Targeted suites: 107 passed across security, audit chain, web3 identity, relay, and security headers (32.29s); 33/33 passed on rate limiter heavy stress suite; Smart contracts: 160 passing test cases across 10 Hardhat suites (100% pass rate).
- Runtime standard: use Python 3.12 for full compatibility.

## Related Docs

- `HARDENING.md`
- `OPERATIONS.md`
- `TROUBLESHOOTING.md`
- `README.md`
- `PRODUCTION_LAUNCH_RUNBOOK.md`


