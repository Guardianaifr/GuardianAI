# Deployment Assets

Ops assets for the hosted deployment model. The firewall stack itself deploys from the repo-root `Dockerfile`
(Railway reads `railway.json`; any Docker host works). See `../docs/architecture/DEPLOYMENT.md` and
`../docs/operations/PRODUCTION_LAUNCH_RUNBOOK.md` for the full runbook.

| Folder | What it holds |
|---|---|
| `production/` | systemd unit, Caddy (HTTPS) config, `.env.production.example`, `setup_production.ps1` / `verify_production.ps1`, and `AGENTIC_MTLS.md` (mutual TLS for agent-to-control-plane traffic) |
| `prometheus/` | Scrape config and alert rules |
| `relay/` | The public GuardianAI relay (approvals + threat feed): `Dockerfile`, Railway and Cloud Run deploy scripts. See [`relay/README.md`](relay/README.md) |

## Prometheus

Files:
- `deploy/prometheus/scrape-config.yaml`
- `deploy/prometheus/guardian-alert-rules.yaml`

Use:
- Merge `scrape_configs` into your Prometheus server config. The backend exposes `/metrics` on port 8001.
- Load `guardian-alert-rules.yaml` via your Prometheus rule files configuration.
