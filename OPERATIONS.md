# GuardianAI Operations Guide

Operational runbook for the current backend and proxy implementation.

## 1. Daily Checks

Role guidance:
- run security-sensitive checks using `auditor` or `admin` account
- reserve `admin` for mutating operations only

1. Readiness:
- `GET /health`
- expect `status=healthy` and HTTP `200`

2. Metrics:
- `GET /metrics`
- verify request counters and process gauges are updating

3. Audit integrity:
- `GET /api/v1/audit-log/verify`
- expect `ok=true`

4. Audit delivery queue:
- `GET /api/v1/audit-log/failures`
- investigate queue growth

## 2. Incident Response Shortcuts

1. Revoke compromised user JWT:
- call `POST /api/v1/auth/revoke` with the bearer token

2. Disable compromised telemetry key:
- `POST /api/v1/api-keys/{id}/revoke`

3. Rotate telemetry key:
- `POST /api/v1/api-keys/{id}/rotate`

4. Replay external audit failures after sink recovery:
- `POST /api/v1/audit-log/retry-failures`
- requires `admin`

## 3. Backup and Restore

1. Primary data store:
- SQLite file `guardian.db`

2. Recommended backup cadence:
- at least daily
- before major upgrades/config changes

3. Minimal backup set:
- `guardian.db`
- deployment env vars (secure secret store)
- `guardian/config/` (if used in your deployment)

4. Restore validation after recovery:
- `GET /health`
- `GET /api/v1/audit-log/verify`
- `GET /api/v1/analytics`

## 4. Capacity and Limits

Tune these based on load profile:
- `GUARDIAN_AUTH_RATE_LIMIT_PER_MIN`
- `GUARDIAN_RATE_LIMIT_PER_MIN`
- `GUARDIAN_TELEMETRY_RATE_LIMIT_PER_MIN`
- `GUARDIAN_USER_RATE_LIMITS_JSON`
- `GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON`
- `GUARDIAN_RATE_LIMIT_BACKEND`
- `GUARDIAN_RATE_LIMIT_REDIS_URL`

Operational notes:
- in-memory limiter state resets on process restart
- distributed mode supports Redis with fallback to in-memory limiter by default
- set `GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN=false` to fail closed when Redis is unavailable

## 5. External Audit Sinks

HTTP sink:
- configure `GUARDIAN_AUDIT_SINK_URL`
- optional bearer token via `GUARDIAN_AUDIT_SINK_TOKEN`
- strict mode blocks on delivery failure when `GUARDIAN_AUDIT_STRICT=true`

Syslog sink:
- configure `GUARDIAN_AUDIT_SYSLOG_HOST` and `GUARDIAN_AUDIT_SYSLOG_PORT`
- strict mode via `GUARDIAN_AUDIT_SYSLOG_STRICT=true`

Splunk sink:
- configure `GUARDIAN_AUDIT_SPLUNK_HEC_URL` + `GUARDIAN_AUDIT_SPLUNK_HEC_TOKEN`
- optional metadata: index/source/sourcetype via `GUARDIAN_AUDIT_SPLUNK_*`

Datadog sink:
- configure `GUARDIAN_AUDIT_DATADOG_API_KEY`
- optional endpoint/service/source/tags via `GUARDIAN_AUDIT_DATADOG_*`

Queue behavior:
- non-strict failures are queued in `audit_delivery_failures`
- process with `POST /api/v1/audit-log/retry-failures`

## 6. TLS and Edge

1. Backend HTTPS enforcement:
- `GUARDIAN_ENFORCE_HTTPS=true` in production

2. Native TLS startup:
- `GUARDIAN_TLS_CERT_FILE`
- `GUARDIAN_TLS_KEY_FILE`

3. Reverse proxy mode:
- ensure proxy sets `x-forwarded-proto=https`

## 7. Maintenance Checklist

Weekly:
1. verify `/health`, `/metrics`, `/api/v1/compliance/report`, `/api/v1/rbac/policy`, `/api/v1/audit-log/summary`, and audit chain integrity
2. review audit failures and retry queue
3. rotate high-risk API keys as policy requires

Monthly:
1. test token revocation and key revocation drills
2. run dependency vulnerability scan
3. verify backup restore procedure in staging

## 8. Hardening Smoke Run

Run an end-to-end hardening smoke test against a running backend:

```bash
python tools/hardening_smoke.py --base-url http://127.0.0.1:8001
```

Optional flags:
- `--admin-user`
- `--admin-pass`
- `--auditor-user`
- `--auditor-pass`
- `--user-user`
- `--user-pass`
- `--guardian-id`
- `--key-name`
