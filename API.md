# GuardianAI API Reference

This document reflects the currently implemented API in `backend/main.py` and the proxy surface.

## Base URLs

- Proxy API: `http://127.0.0.1:8081`
- Backend API: `http://127.0.0.1:8001`

## Authentication

Protected backend routes support:
- `Authorization: Bearer <jwt>` (preferred)
- `Authorization: Basic <base64(user:pass)>` (fallback for compatibility)

JWT tokens are issued by:
- `POST /api/v1/auth/token`

RBAC roles:
- `admin` (full access)
- `auditor` (read-only audit visibility)
- `user` (general analytics/events/export access)

OpenAPI:
- `GET /openapi.json` includes request/response schemas and examples for hardening endpoints.

## Proxy Endpoints

### `POST /v1/chat/completions`
OpenAI-compatible proxy endpoint with Guardian filtering/rate-limit controls.

### `GET /health`
Proxy process health endpoint.

## Backend Endpoints

### Health and Metrics

### `GET /health`
Returns readiness-like status with component details.

Example fields:
- `status`: `healthy` or `unhealthy`
- `timestamp`
- `uptime_sec`
- `components.database.ok`
- `components.metrics_enabled`
- `components.https_enforced`
- `components.telemetry_requires_api_key`
- `components.audit_sink_configured`

When DB health fails, returns `503`.

### `GET /metrics`
Prometheus-style plaintext metrics.
Returns `404` when metrics are disabled.

Key metrics:
- `guardian_http_requests_total`
- `guardian_http_request_latency_avg_ms`
- `guardian_http_requests_per_second_1m`
- `guardian_process_cpu_percent`
- `guardian_process_memory_bytes`
- `guardian_http_status_total{code="<status>"}`

### Authentication

### `POST /api/v1/auth/token`
Issues JWT using Basic credentials.

Response fields:
- `access_token`
- `token_type` (`bearer`)
- `expires_in`
- `user`
- `role`

### `POST /api/v1/auth/revoke`
Revokes the current bearer JWT (by `jti`).
Requires Bearer token.

Response fields:
- `status`
- `revoked_jti`
- `revoked_by`

### `GET /api/v1/auth/revocations`
Lists revoked JWT entries for incident-response visibility.
Role required: `admin` or `auditor`.

Query params:
- `limit` (default `100`, max `1000`)
- `include_expired` (default `false`)

### `POST /api/v1/auth/revocations/prune`
Prunes revoked-token entries from storage.
Role required: `admin`.
Action is written to immutable audit log (`auth_prune_revocations`).

Query params:
- `expired_only` (default `true`)

### `GET /api/v1/auth/sessions`
Lists tracked JWT sessions (`issued_tokens` inventory).
Role required: `admin` or `auditor`.

Query params:
- `limit` (default `100`, max `1000`)
- `include_expired` (default `false`)
- `include_revoked` (default `true`)

### `POST /api/v1/auth/sessions/revoke-user`
Revokes tracked sessions for a target user and writes immutable audit entry (`auth_revoke_user_sessions`).
Role required: `admin`.

Request body:
- `username` (string, required)
- `active_only` (boolean, default `true`)
- `reason` (optional string)

### `POST /api/v1/auth/sessions/revoke-jti`
Revokes a single tracked session by `jti` and writes immutable audit entry (`auth_revoke_session_jti`).
Role required: `admin`.

Request body:
- `jti` (string, required)
- `reason` (optional string)

### `GET /api/v1/auth/whoami`
Returns current authenticated principal, auth mode, and effective permission scopes.

Response fields:
- `user`
- `role`
- `auth_type` (`basic` or `bearer`)
- `permissions` (role-derived scope list)

### API Key Management

### `POST /api/v1/api-keys`
Creates a managed telemetry API key.
Role required: `admin`.

Request body:
- `key_name` (string, unique)

Returns metadata plus one-time plaintext `api_key`.

### `GET /api/v1/api-keys`
Lists managed API keys (metadata only).
Role required: `admin` or `auditor`.

### `POST /api/v1/api-keys/{key_id}/revoke`
Marks an API key inactive.
Role required: `admin`.

### `POST /api/v1/api-keys/{key_id}/rotate`
Rotates key material for an existing key and returns new plaintext `api_key`.
Role required: `admin`.

### Telemetry and Analytics

### `POST /api/v1/telemetry`
Ingests telemetry events.

Behavior:
- per-identity rate limiting
- optional telemetry API-key enforcement
- persists events to SQLite
- writes admin audit entries for `admin_action`
- forwards audit entries to configured external sinks

### `GET /api/v1/events?limit=<n>`
Returns recent telemetry events.

### `GET /api/v1/analytics`
Returns aggregate analytics and latency/block-rate summaries.

### `GET /api/v1/export/json`
Exports telemetry events as JSON.

### `GET /api/v1/export/csv`
Exports telemetry events as CSV.

### Audit Log and Integrity

### `GET /api/v1/audit-log?limit=<n>`
Returns audit log entries, including chain fields:
- `signature`
- `prev_hash`
- `entry_hash`
Role required: `admin` or `auditor`.

### `GET /api/v1/audit-log/verify`
Verifies tamper-evident hash chain across audit log entries.
Role required: `admin` or `auditor`.

Response:
- `ok` (boolean)
- `entries` (checked count)
- `failed_id` and `reason` when verification fails

### `GET /api/v1/audit-log/summary`
Returns audit observability summary:
- hash-chain status
- total/hashed/legacy audit entry counts
- recent admin action count (24h)
- queued delivery-failure totals and sink breakdown
Role required: `admin` or `auditor`.

### `GET /api/v1/audit-log/failures?limit=<n>`
Lists queued external audit-delivery failures.
Role required: `admin` or `auditor`.

### `POST /api/v1/audit-log/retry-failures?limit=<n>`
Retries queued audit-delivery failures.
Role required: `admin`.

Response:
- `retried`
- `resolved`
- `failed`

### Compliance Snapshot

### `GET /api/v1/compliance/report`
Returns a hardening/compliance posture snapshot across key controls.
Role required: `admin` or `auditor`.

Response fields:
- `status` (`pass` | `warn` | `fail`)
- `timestamp`
- `summary.passed`
- `summary.warnings`
- `summary.failed`
- `controls[]` with per-control `status` and `detail`

### `GET /api/v1/rbac/policy`
Returns the RBAC role-permission catalog and endpoint access matrix.
Role required: `admin` or `auditor`.

Response fields:
- `generated_at`
- `roles` (map of role -> permission scopes)
- `endpoints[]` with `method`, `path`, `allowed_roles`, and `permission`

### Realtime

### `WS /ws/threats`
Broadcast stream for incoming telemetry events.

## Common Status Codes

- `200` success
- `400` invalid request payload/parameters
- `401` authentication failure or revoked token
- `403` blocked by policy (proxy path)
- `404` resource/feature unavailable
- `429` rate limit exceeded
- `503` dependency unavailable (strict external audit sink failures, unhealthy readiness)

## Environment Variables (Backend)

### Core Auth and Limits
- `GUARDIAN_ADMIN_USER`
- `GUARDIAN_ADMIN_PASS`
- `GUARDIAN_AUDITOR_USER`
- `GUARDIAN_AUDITOR_PASS`
- `GUARDIAN_USER_USER`
- `GUARDIAN_USER_PASS`
- `GUARDIAN_JWT_SECRET`
- `GUARDIAN_JWT_ISSUER`
- `GUARDIAN_JWT_EXPIRES_MIN`
- `GUARDIAN_AUTH_RATE_LIMIT_PER_MIN`
- `GUARDIAN_RATE_LIMIT_PER_MIN`
- `GUARDIAN_TELEMETRY_RATE_LIMIT_PER_MIN`
- `GUARDIAN_USER_RATE_LIMITS_JSON`
- `GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON`
- `GUARDIAN_RATE_LIMIT_BACKEND` (`memory` | `redis` | `auto`)
- `GUARDIAN_RATE_LIMIT_REDIS_URL`
- `GUARDIAN_RATE_LIMIT_REDIS_KEY_PREFIX`
- `GUARDIAN_RATE_LIMIT_REDIS_TIMEOUT_SEC`
- `GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN`
- `GUARDIAN_TELEMETRY_REQUIRE_API_KEY`

### Transport and Metrics
- `GUARDIAN_ENFORCE_HTTPS`
- `GUARDIAN_TLS_CERT_FILE`
- `GUARDIAN_TLS_KEY_FILE`
- `GUARDIAN_METRICS_ENABLED`

### Audit Sinks
- `GUARDIAN_AUDIT_SINK_URL`
- `GUARDIAN_AUDIT_SINK_TOKEN`
- `GUARDIAN_AUDIT_TIMEOUT_SEC`
- `GUARDIAN_AUDIT_RETRIES`
- `GUARDIAN_AUDIT_STRICT`
- `GUARDIAN_AUDIT_SYSLOG_HOST`
- `GUARDIAN_AUDIT_SYSLOG_PORT`
- `GUARDIAN_AUDIT_SYSLOG_TIMEOUT_SEC`
- `GUARDIAN_AUDIT_SYSLOG_STRICT`
- `GUARDIAN_AUDIT_SPLUNK_HEC_URL`
- `GUARDIAN_AUDIT_SPLUNK_HEC_TOKEN`
- `GUARDIAN_AUDIT_SPLUNK_INDEX`
- `GUARDIAN_AUDIT_SPLUNK_SOURCE`
- `GUARDIAN_AUDIT_SPLUNK_SOURCETYPE`
- `GUARDIAN_AUDIT_SPLUNK_STRICT`
- `GUARDIAN_AUDIT_DATADOG_LOGS_URL`
- `GUARDIAN_AUDIT_DATADOG_API_KEY`
- `GUARDIAN_AUDIT_DATADOG_SERVICE`
- `GUARDIAN_AUDIT_DATADOG_SOURCE`
- `GUARDIAN_AUDIT_DATADOG_TAGS`
- `GUARDIAN_AUDIT_DATADOG_STRICT`
