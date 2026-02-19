# Deployment Manifests

This folder contains baseline deployment assets for Kubernetes and Prometheus.

## Kubernetes

Files:
- `deploy/k8s/namespace.yaml`
- `deploy/k8s/guardian-backend.yaml`
- `deploy/k8s/guardian-proxy.yaml`

Apply:
```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/guardian-backend.yaml
kubectl apply -f deploy/k8s/guardian-proxy.yaml
```

Notes:
- Update image tags before production rollout.
- Replace secret placeholders in `guardian-backend-secrets`.
- Backend manifest defaults to Redis distributed rate limiting with fail-closed mode.

## Prometheus

Files:
- `deploy/prometheus/scrape-config.yaml`
- `deploy/prometheus/guardian-alert-rules.yaml`

Use:
- Merge `scrape_configs` into your Prometheus server config.
- Load `guardian-alert-rules.yaml` via your Prometheus rule files configuration.
