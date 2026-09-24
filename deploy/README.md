# Deployment Assets

This folder contains ops assets for the hosted deployment model.
The service itself deploys from the repo-root `Dockerfile` (Railway reads
`railway.json`; any Docker host works) — see `../docs/architecture/DEPLOYMENT.md` and
`../docs/operations/PRODUCTION_LAUNCH_RUNBOOK.md` for the full runbook, including the
systemd/Caddy patterns for Oracle Cloud VMs under `production/`.

## Prometheus

Files:
- `deploy/prometheus/scrape-config.yaml`
- `deploy/prometheus/guardian-alert-rules.yaml`

Use:
- Merge `scrape_configs` into your Prometheus server config.
- Load `guardian-alert-rules.yaml` via your Prometheus rule files configuration.
