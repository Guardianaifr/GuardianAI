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
- Guardian returns `403` for blocked prompts (AI Firewall, SystemPromptGuard, InputFilter).
- Guardian returns `413` if the request payload exceeds 10MB (`MAX_CONTENT_LENGTH`).
- Guardian returns `429` for rate limit violations (atomic Redis token bucket).
- Guardian returns proxied upstream response when allowed.
- RFC 9110 Hop-by-Hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Upgrade`, etc.) are stripped before forwarding.
- Real-time SSE streaming responses (`"stream": true`) are dynamically inspected for system prompt leaks (OWASP LLM07).

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

Real-time threat event stream (requires first-message authentication payload with admin/auditor token).

Example URL:
- `ws://127.0.0.1:8001/ws/threats`

## 3) Authentication & RBAC API

### POST `/api/v1/auth/token`
Issue JWT token pair (access + refresh) using Argon2id-authenticated credentials.

### POST `/api/v1/auth/refresh`
Rotate refresh token and issue a new access token pair.

### POST `/api/v1/auth/revoke`
Revoke a JWT token by `jti` ID.

### GET `/api/v1/auth/sessions`
List active sessions for the authenticated principal.

### GET `/api/v1/auth/lockout`
Query account lockout status (admin only).

### GET `/api/v1/rbac/whoami`
Return authenticated principal identity, tenant, and resolved RBAC permissions.

### GET `/api/v1/rbac/policy`
Return full RBAC permission hierarchy and role matrices.

## 4) Compliance & Audit API

### GET `/api/compliance/evidence`
Retrieve cryptographic compliance evidence package with HMAC-SHA256 signature verification.

## 5) ERC-8004 Identity Registry API

All three endpoints are inactive unless `GUARDIAN_ERC8004_ENABLED=true`. See whitepaper Feature 39 and `.env.example`.

### POST `/api/v1/erc8004/register`

Queue an agent for canonical-registry registration (admin only). Body:

```json
{
  "agent_id": "my-agent",
  "chain": "base-sepolia",
  "owner_address": "0x..."
}
```

- `chain` optional — omit to use all `GUARDIAN_ERC8004_CHAINS`.
- `owner_address` optional — when supplied (register-then-transfer policy), the identity NFT is transferred to this address after the passport metadata link is written; otherwise the identity stays custodial.
- Returns `202` with per-target queue status, `400` on misconfiguration/rejection, `403` non-admin, `404` unknown agent.

### GET `/api/v1/erc8004/status/{agent_id}`

Registration queue state for one agent (tenant-scoped: admins global, users own tenant). Returns per-chain rows with `status` (`pending|registering|metadata|confirmed|failed`), `token_id`, `tx_hash`, `retries`, `owner_address`.

### GET `/api/v1/erc8004/agents/{agent_id}.json`

Public ERC-8004 registration file served at the on-chain `agentURI`. 404 while the feature is disabled or the agent is unknown. Contains no passport identifiers beyond what the spec requires.

## 6) Common Status Codes

- `200`: success
- `401`: backend auth failure (protected backend routes)
- `403`: blocked by security policy / CSRF validation failure
- `413`: request body exceeds maximum 1MB payload limit
- `429`: rate limit exceeded (fail-closed token bucket)
- `502`: upstream connectivity failure

## 7) Current Behavior Notes

- Security mode is configured via YAML (`guardian/config/*.yaml`).
- Passwords are encrypted with Argon2id (`t=7, m=64MB, p=4`) with automatic legacy SHA-256 migration.
- Runtime decisions are made by Input Filter, AI Firewall, Threat Feed, Base64 detector, and Output Validator.
- All protected API routes enforce standard security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).

