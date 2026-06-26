# GuardianAI API Reference

This reference documents the currently implemented endpoints.

## Base URLs

- Guardian Proxy: `http://127.0.0.1:8081`
- Backend API: `http://127.0.0.1:8001`

## 1) Proxy API (OpenAI-compatible)

### POST `/v1/chat/completions`

Send chat completion requests through Guardian.

Example:
```bash
curl -X POST http://127.0.0.1:8081/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

Notes:
- Guardian may return `403` for blocked prompts.
- Guardian may return `429` for rate limit violations.
- Guardian returns proxied upstream response when allowed.

### GET `/health`

Proxy health check.

Example response:
```json
{
  "status": "ok",
  "component": "guardian_proxy"
}
```

## 2) Backend Telemetry API

### GET `/health`

Backend health check.

### POST `/api/v1/telemetry`

Ingests a telemetry event from proxy/runtime components.

### GET `/api/v1/events`

Returns recent events.

Query params:
- `limit` (optional): number of events

### GET `/api/v1/analytics`

Returns aggregate analytics summary.

### GET `/api/v1/audit-log`

Returns immutable admin/audit log records.

### GET `/api/v1/export/json`

Exports events as JSON.

### GET `/api/v1/export/csv`

Exports events as CSV.

### WebSocket `/ws/threats`

Real-time threat event stream.

Example URL:
- `ws://127.0.0.1:8001/ws/threats`

## 3) Common Status Codes

- `200`: success
- `401`: backend auth failure (protected backend routes)
- `403`: blocked by security policy
- `429`: rate limit exceeded
- `502`: upstream connectivity failure

## 4) Current Behavior Notes

- Security mode is configured via YAML (`guardian/config/*.yaml`).
- Runtime decisions are made by Input Filter, AI Firewall, Threat Feed, Base64 detector, and Output Validator.
- API docs in this file are intentionally limited to endpoints that exist in current code.
