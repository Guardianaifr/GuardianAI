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
- Guardian returns `401 Unauthorized` with `WWW-Authenticate: Bearer error="invalid_token", error_description="..."` header (RFC 6750) when agent attestation is required but missing, invalid, expired, replayed, or payload-mismatched.
- Guardian returns `403 Forbidden` for blocked prompts (AI Firewall, SystemPromptGuard, InputFilter) and for validly authenticated agents that are unregistered, revoked, or below required trust tier.
- Guardian returns `413 Payload Too Large` if the request payload exceeds 10MB (`MAX_CONTENT_LENGTH`) or 1MB on backend endpoints.
- Guardian returns `429 Too Many Requests` for rate limit violations (atomic Redis token bucket).
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

All three endpoints are inactive unless `GUARDIAN_ERC8004_ENABLED=true`. See ../whitepaper/WHITEPAPER_PUBLIC.md Feature 39 and `.env.example`.

### POST `/api/v1/erc8004/register`

Queue an agent for canonical-registry registration (admin only). Body:

```json
{
  "agent_id": "my-agent",
  "chain": "monad-testnet",
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

## 6) Guardian Relayer & Attestation API (RPC Relay Port 8546)

### POST `/api/v1/attest`

Evaluates agent prompt and transaction parameters using the deterministic rules engine (InputFilter, TransactionAnalyzer, AgentPolicy allowlists, and OutflowTracker spending caps). Returns a signed EIP-712 `SafetyAttestation` and pre-encoded `wrapped_calldata` for `GuardianPolicyGuard.executeWithAttestation(...)`.

**Request Body:**
```json
{
  "agent_id": "agent-monad-01",
  "target": "0x1234567890abcdef1234567890abcdef12345678",
  "data": "0xa9059cbb...",
  "value": 0,
  "prompt": "Swap 10 USDC for MON",
  "nonce": 12345678,
  "ttl_seconds": 300
}
```

**Response (`200 OK` - Approved):**
```json
{
  "status": "approved",
  "risk_score": 0,
  "reasons": [],
  "attestation": {
    "agentId": "0x...",
    "targetContract": "0x...",
    "calldataHash": "0x...",
    "value": 0,
    "riskScore": 0,
    "nonce": 12345678,
    "deadline": 1788462000
  },
  "signature": "0x...",
  "policy_guard": "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
  "wrapped_calldata": "0x3cb7461c..."
}
```

**Response (`200 OK` - Blocked):**
```json
{
  "status": "blocked",
  "risk_score": 100,
  "reasons": [
    "Function selector 0xdeadbeef not in agent allowlist. Permitted: ['0x095ea7b3', '0xa9059cbb']"
  ],
  "attestation": null,
  "signature": null,
  "policy_guard": "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
  "wrapped_calldata": null
}
```

## 7) Category Labs Mera Passkey Memory Enclave API

Blind-storage and cryptographic integrity endpoints for client-side WebAuthn PRF encrypted agent memories. Server persists only AES-256-GCM ciphertext blobs with zero knowledge of plaintext or keys.

### POST `/api/v1/passport/memory`

Blind-stores an encrypted memory record.

**Request Body:**
```json
{
  "agent_id": "guardian-alpha",
  "session_id": "session-101",
  "seq_no": 1,
  "ciphertext_b64": "vA7G4...",
  "iv_b64": "123456789012",
  "aad": "guardian-alpha:session-101:1:1789220000",
  "timestamp": 1789220000.0
}
```

### GET `/api/v1/passport/memory/{agent_id}`

Retrieves all blind-stored ciphertext records for an agent ordered by sequence number.

### POST `/api/v1/passport/memory/{agent_id}/tamper`

Adversarial audit endpoint simulating active database tampering (flips ciphertext bits or corrupts AAD) to verify client-side tripwires.

### GET `/api/v1/passport/tamper-alerts`

Returns cryptographic tamper violation logs and quarantined agent records.

## 8) Common Status Codes
 
- `200`: success
- `401`: unauthorized — missing, invalid, expired, or replayed agent attestation (with `WWW-Authenticate` header per RFC 6750), or backend auth failure
- `403`: forbidden — blocked by security policy, unregistered/revoked agent, or CSRF validation failure
- `413`: request body exceeds payload limit (10MB proxy / 1MB backend)
- `429`: rate limit exceeded (fail-closed token bucket)
- `502`: upstream connectivity failure
- `503`: attestation service unavailable

## 8) Web3 JSON-RPC Security Relay API (Port 8546)

The Web3 JSON-RPC relay sits between crypto wallets/agents and the Monad Testnet node (defaulting to the dedicated QuickNode RPC endpoint).

### Supported Methods & Point-of-Interaction Enforcement:
- `eth_sendRawTransaction`: Inspects signed RLP transaction calldata, recovers the `from` sender address, validates EIP-155 replay protection (`chainId == 10143`), verifies `X-Guardian-Agent-Attestation`, and cross-references against on-chain ERC-8004 identity registrations (`ownerOf` checks).
- `eth_sendTransaction`: Intercepts transaction parameters, verifies EIP-712 / JWT agent attestations, and validates against active agent policies.
- Other EVM RPC methods (`eth_call`, `eth_blockNumber`, `eth_getBalance`, etc.): Proxied upstream with fail-closed security guarantees.

### Error Format:
Blocked transactions return standard JSON-RPC 2.0 error responses:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "Guardian Network Block: Raw transaction missing EIP-155 replay protection: GuardianAI exclusively targets Monad Testnet (Chain ID 10143)"
  }
}
```

## 9) Current Behavior Notes

- Security mode is configured via YAML (`guardian/config/*.yaml`).
- Exclusively targets **Monad Testnet (Chain ID 10143)** with automated SQLite schema/row migration for legacy databases.
- Passwords are encrypted with Argon2id (`t=7, m=64MB, p=4`) with automatic legacy SHA-256 migration.
- Runtime decisions are made by Input Filter, AI Firewall, Threat Feed, Base64 detector, AgentPolicy allowlists, OutflowTracker, and Output Validator.
- Fail-Closed Policy: Middleware strictly rejects pre-wrapped calldata and blocks calls when relayer is unreachable.
- All protected API routes enforce standard security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).

