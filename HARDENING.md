# GuardianAI Hardening Guide

This guide maps to implemented controls in the current backend and proxy stack.

## 1. Identity and Authentication

1. Set strong secrets:
- `GUARDIAN_ADMIN_PASS`
- `GUARDIAN_JWT_SECRET`

2. Configure role-specific backend users:
- `GUARDIAN_AUDITOR_USER` / `GUARDIAN_AUDITOR_PASS`
- `GUARDIAN_USER_USER` / `GUARDIAN_USER_PASS`

3. Prefer Bearer JWT for backend access:
- obtain token from `POST /api/v1/auth/token`
- avoid long-lived Basic usage outside local admin setup

4. Use token revocation for incident response:
- `POST /api/v1/auth/revoke`
- revoked tokens are enforced server-side via `jti` checks
- list revocations: `GET /api/v1/auth/revocations`
- prune expired revocations: `POST /api/v1/auth/revocations/prune`

5. Enforce least privilege by role:
- `admin`: API key lifecycle + retrying audit delivery queue
- `auditor`: read audit log, verify chain, inspect queue
- `user`: analytics, event views, exports
- inspect policy map via `GET /api/v1/rbac/policy` (auditor/admin)

6. Enable auth endpoint throttling:
- tune `GUARDIAN_AUTH_RATE_LIMIT_PER_MIN` to reduce brute-force risk

## 2. API Key Security

1. Manage telemetry keys via backend APIs:
- create: `POST /api/v1/api-keys`
- rotate: `POST /api/v1/api-keys/{id}/rotate`
- revoke: `POST /api/v1/api-keys/{id}/revoke`

2. Enforce telemetry key requirement in production:
- `GUARDIAN_TELEMETRY_REQUIRE_API_KEY=true`

3. Use key names and per-key limits:
- `GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON`
- rotate compromised keys immediately

## 3. Rate Limiting

1. Set sane defaults:
- `GUARDIAN_RATE_LIMIT_PER_MIN`
- `GUARDIAN_TELEMETRY_RATE_LIMIT_PER_MIN`

2. Apply per-user overrides where needed:
- `GUARDIAN_USER_RATE_LIMITS_JSON` (JSON object)

3. Example override values:
```json
{
  "admin": 300,
  "auditor": 120
}
```

4. For multi-instance deployments, enable distributed limits:
- `GUARDIAN_RATE_LIMIT_BACKEND=redis` (or `auto`)
- `GUARDIAN_RATE_LIMIT_REDIS_URL=redis://host:6379/0`
- set `GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN=false` for strict dependency enforcement

## 4. Transport Security

1. Enforce HTTPS at backend edge in production:
- `GUARDIAN_ENFORCE_HTTPS=true`

2. Run backend with TLS cert/key:
- `GUARDIAN_TLS_CERT_FILE`
- `GUARDIAN_TLS_KEY_FILE`

3. If behind a reverse proxy, ensure `x-forwarded-proto=https` is set correctly.

## 5. Audit Logging and Integrity

1. Keep local audit chain enabled:
- admin events are hash-chained (`prev_hash`, `entry_hash`)
- verify integrity via `GET /api/v1/audit-log/verify`
- monitor aggregate state via `GET /api/v1/audit-log/summary`

2. Configure external audit sinks:
- HTTP sink (`GUARDIAN_AUDIT_SINK_*`)
- Syslog sink (`GUARDIAN_AUDIT_SYSLOG_*`)
- Splunk HEC sink (`GUARDIAN_AUDIT_SPLUNK_*`)
- Datadog Logs sink (`GUARDIAN_AUDIT_DATADOG_*`)

3. Use strict mode in higher-assurance environments:
- `GUARDIAN_AUDIT_STRICT=true`
- `GUARDIAN_AUDIT_SYSLOG_STRICT=true`

4. Operate retry queue:
- inspect failures: `GET /api/v1/audit-log/failures`
- replay failures: `POST /api/v1/audit-log/retry-failures`

## 6. Monitoring and Readiness

1. Integrate readiness checks:
- `GET /health` (returns `503` when DB dependency is unhealthy)

2. Scrape Prometheus metrics:
- `GET /metrics`
- disable only if explicitly required: `GUARDIAN_METRICS_ENABLED=false`

3. Review compliance snapshot:
- `GET /api/v1/compliance/report`
- use this as a quick control-gap dashboard (pass/warn/fail + per-control details)

4. Alert recommendations:
- elevated 401/429 rates
- sustained audit sink failures
- unhealthy readiness responses

## 7. Host and Runtime Practices

1. Run as non-root user where possible.
2. Restrict inbound/outbound network paths.
3. Keep dependency scanning in CI (e.g., `pip-audit`).
4. Backup `guardian.db` and config/env secrets regularly.
