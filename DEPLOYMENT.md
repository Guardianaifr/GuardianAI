# GuardianAI Deployment Guide

This guide is aligned with the current repository behavior.

## Prerequisites

- Python 3.10-3.12 recommended (3.14 works with Presidio fallback caveats)
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
- Keep upstream service on localhost/private network only.
- Expose only Guardian ingress as needed.
- Enable host-level firewall and log rotation.
- Run `python -m pytest tests -q` before release.

## Current Validation Snapshot

- Tests: `61/61` passing (latest local validation)
- Known caveat: Python 3.14 can trigger Presidio compatibility warnings.

## Related Docs

- `HARDENING.md`
- `OPERATIONS.md`
- `TROUBLESHOOTING.md`
- `README.md`
- `deploy/README.md`

## Kubernetes + Prometheus Baseline

This repo now includes baseline deployment manifests and monitoring assets:

- Kubernetes manifests:
  - `deploy/k8s/namespace.yaml`
  - `deploy/k8s/guardian-backend.yaml`
  - `deploy/k8s/guardian-proxy.yaml`
- Prometheus assets:
  - `deploy/prometheus/scrape-config.yaml`
  - `deploy/prometheus/guardian-alert-rules.yaml`

Quick apply:
```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/guardian-backend.yaml
kubectl apply -f deploy/k8s/guardian-proxy.yaml
```

