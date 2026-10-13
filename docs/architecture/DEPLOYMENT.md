# GuardianAI Deployment Guide

This guide matches the repository as of October 2026. It covers the self-hosted firewall stack (proxy +
backend) and lists the hosted services behind aiguardian.dev.

## Prerequisites

- Python 3.12 (project standard; `.venv312`)
- Docker (for the Compose stack)
- An upstream model/service endpoint for the proxy to protect (default: `http://127.0.0.1:8080`)

## Local run (Python)

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure (optional):
- Default config: `guardian/config/config.yaml`
- Override with an env var:
```bash
# Windows PowerShell
$env:GUARDIAN_CONFIG="guardian/config/config.yaml"
```
- Secrets and feature flags: copy `.env.example` to `.env` and fill it in.

3. Start services:
```bash
python guardianctl.py setup      # interactive setup wizard
python guardianctl.py start      # backend + Guardian proxy
# or everything in one step:
python guardianctl.py one-click --target-url http://127.0.0.1:8080
```

Other `guardianctl.py` commands: `status`, `hardening-check` (risky public port exposure), `dashboard`.

4. Verify health:
- Proxy: `http://127.0.0.1:8081/health`
- Backend: `http://127.0.0.1:8001/health` (OpenAPI docs at `/docs`)

## Docker Compose

```bash
cp .env.example .env
docker compose up -d
```

Services: `redis` (rate limits, lockouts), `guardian` (proxy on 8081, backend on 8001, data in the
`guardian-data` volume) and `frontend` (nginx serving `website/` on port 3000).

## Runtime ports (default)

- Upstream model/service: `127.0.0.1:8080`
- Guardian proxy: `127.0.0.1:8081` (binds loopback unless `GUARDIAN_PROXY_HOST=0.0.0.0`)
- Backend API/dashboard: `127.0.0.1:8001`
- Web3 RPC relay / attestation API (`python tools/run_relay.py`): `127.0.0.1:8546`

## Hosted services (aiguardian.dev)

| Service | Where | Deploy |
|---|---|---|
| Website, Attack Lab, Console, Mera console | Firebase Hosting (`firebase.json`, site `aiguardian-site`) | `firebase deploy --only hosting`; see `website/README.md` |
| Public relay (approvals, threat feed) | Railway, `guardian-relay-production.up.railway.app` | `deploy/relay/deploy-railway.ps1`; see `deploy/relay/README.md` |
| Hosted ElizaOS agent | Railway, `guardian-eliza-production.up.railway.app` | see `packages/eliza-host/README.md` |
| Envio indexer | Envio Cloud (built from the `envio` branch) | see `metropolis/indexer/README.md` |

The repo-root `railway.json` deploys the full one-click firewall stack from the root `Dockerfile`; the relay
and the ElizaOS host use their own Railway configs.

## Production checklist

- Change default admin credentials (`GUARDIAN_ADMIN_PASS`) and set a high-entropy `GUARDIAN_JWT_SECRET`.
- Set `GUARDIAN_ENV=production`: weak fallbacks (SHA-256 password hashes, XOR secrets) are refused and Redis becomes mandatory for lockouts.
- **Financial controls (decision FL_008):** slippage-setting via GuardianAI is unsupported and hard-blocked until a valid 1inch API key is configured for depth verification.
- Rate limiting: with `GUARDIAN_ENV=production` the backend refuses to start unless `GUARDIAN_RATE_LIMIT_BACKEND=redis` and `GUARDIAN_RATE_LIMIT_REDIS_URL` are set. Outside production the default `memory` backend enforces limits per worker only.
- Keep the upstream service on localhost or a private network; expose only the Guardian ingress.
- Enable a host-level firewall and log rotation.
- For the relay: use a dedicated `GUARDIAN_ATTESTATION_SIGNER_KEY` (never the deployer key) and run a single instance.
- Run `pytest tests -q` before release.

## Current validation snapshot (October 2026)

From the repository README test table: Hardhat 271 passing; Python suites 1,490+ passing; Mera 26 Vitest +
166 hard-audit assertions; Envio indexer 48; agent middleware 49 + 15; hosted ElizaOS agent 10; explorer 52.

## Related docs

- `HARDENING.md`
- `../operations/OPERATIONS.md`
- `../operations/TROUBLESHOOTING.md`
- `../operations/PRODUCTION_LAUNCH_RUNBOOK.md`
- `../../deploy/README.md`
- `../../README.md`
