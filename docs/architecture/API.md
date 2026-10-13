# GuardianAI API Reference

This reference documents the currently implemented endpoints. Section 11 lists every backend route; the backend also serves interactive OpenAPI docs at `http://127.0.0.1:8001/docs`.

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

### Other proxy routes

Any other path is forwarded to the upstream (`proxy.target_url`) after the same checks, so `/v1/chat/completions` is not special-cased. Admin routes on the proxy (admin Bearer token): `POST /api/reload-model`, `/api/threat-feed/{status,refresh,add-pattern,remove-pattern,webhook,test,export,metrics}`, `GET /api/compliance/evidence`, `GET /api/admin/honeypot/{profiles,analytics}`. `GET /debug/info` is also admin only.

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

Returns immutable admin/audit log records (see section 4 for summary and verification).

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
Issue a JWT access token (`token_type: bearer`, `expires_in: 3600`). Credentials are sent as HTTP Basic auth and verified against Argon2id hashes. Rate limited and subject to account lockout.

```bash
curl -X POST http://127.0.0.1:8001/api/v1/auth/token -u admin:$GUARDIAN_ADMIN_PASS
```

`POST /api/v1/auth/login` and `GET /api/v1/auth/whoami` are the session-cookie equivalents used by the dashboard; `POST /login` and `GET /logout` serve the legacy `/site` pages.

### GET `/api/v1/auth/whoami`
Authenticated principal, role, tenant and effective permissions.

### Sessions and revocation
- `GET /api/v1/auth/sessions` lists active sessions (JTIs).
- `POST /api/v1/auth/revoke` revokes one token by `jti`.
- `POST /api/v1/auth/sessions/revoke-self`, `/revoke-self-jti`, `/revoke-user`, `/revoke-jti`, `/revoke-all` revoke sessions by scope (the last three are admin only).
- `GET /api/v1/auth/revocations` and `POST /api/v1/auth/revocations/prune` inspect and prune the revocation list (admin).

Refresh-token models exist in `backend/auth.py`, but no HTTP route issues or rotates refresh tokens yet.

### Lockouts
- `GET /api/v1/auth/lockouts` lists locked accounts (admin).
- `POST /api/v1/auth/lockouts/clear` clears a lockout (admin).

### GET `/api/v1/rbac/policy`
Full RBAC role and permission matrix.

## 4) Compliance & Audit API

### GET `/api/compliance/evidence` (proxy, port 8081)
Signed compliance evidence package (HMAC-SHA256), served by the Guardian proxy. Admin token required.

### Backend (port 8001)
- `GET /api/v1/compliance/report`: compliance report.
- `GET /api/v1/audit-log`, `/audit-log/summary`, `/audit-log/verify` (tamper-evident hash chain check), `/audit-log/failures`, `POST /api/v1/audit-log/retry-failures` (external sink retries).

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

## 6) Guardian Relayer & Attestation API (RPC Relay, port 8546)

Run locally with `python tools/run_relay.py`. The public deployment (`https://guardian-relay-production.up.railway.app`, see `deploy/relay/README.md`) exposes only `GET /health`, `POST /api/v1/attest`, `GET /api/v1/agents/<id>/rules` and `GET /api/v1/threat-oracle/feed`.

| Route | Purpose |
|---|---|
| `GET /health`, `GET /stats` | Health and counters |
| `POST /api/v1/attest` | Evaluate and sign an approval (below) |
| `GET /api/v1/agents/<agent_id>/rules` | Per-agent rules (public read) |
| `PUT /api/v1/agents/<agent_id>/rules` | Update per-agent rules (admin token) |
| `GET /api/v1/threat-oracle/feed` | Deterministic, digest-protected scam list read by the Chainlink CRE workflow |
| `GET/POST /rules`, `GET/POST /whitelist`, `DELETE /whitelist/<address>` | Backend-to-relay sync (not public) |
| `POST /` | JSON-RPC proxy to Monad testnet (section 9) |

With `GUARDIAN_X402_ENABLED=true`, approvals are pay-per-call (x402, USDC on Monad testnet).

### POST `/api/v1/attest`

Evaluates agent prompt and transaction parameters using the deterministic rules engine (InputFilter, TransactionAnalyzer, AgentPolicy allowlists, and OutflowTracker spending caps). Returns a signed EIP-712 `SafetyAttestation` and pre-encoded `wrapped_calldata` for `GuardianPolicyGuard.executeWithAttestation(...)`.

For a `GuardianAgentWallet`, add `"wallet": "0x..."`: the attestation is then bound to that wallet (EIP-712 domain) and the agent sends it with `GuardianAgentWallet.execute(...)`. Agents registered in `config/agent_passkey_identities.json` must also send a Mera passkey-signed agent card (`guardian/relayer/agent_card.py`); approved responses then include `"agent_identity": "passkey-verified"`. `transferFrom` pulls through PolicyGuard need an EIP-712 authorization signed by the asset owner.

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

## 8) Common Status Codes
 
- `200`: success
- `401`: unauthorized — missing, invalid, expired, or replayed agent attestation (with `WWW-Authenticate` header per RFC 6750), or backend auth failure
- `403`: forbidden — blocked by security policy, unregistered/revoked agent, or CSRF validation failure
- `413`: request body exceeds payload limit (10MB proxy / 1MB backend)
- `429`: rate limit exceeded (fail-closed token bucket)
- `502`: upstream connectivity failure
- `503`: attestation service unavailable

## 9) Web3 JSON-RPC Security Relay API (port 8546)

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

## 10) Current Behavior Notes

- Security mode is configured via YAML (`guardian/config/*.yaml`).
- Exclusively targets **Monad Testnet (Chain ID 10143)** with automated SQLite schema/row migration for legacy databases.
- Passwords are encrypted with Argon2id (`t=7, m=64MB, p=4`) with automatic legacy SHA-256 migration.
- Runtime decisions are made by Input Filter, AI Firewall, Threat Feed, Base64 detector, AgentPolicy allowlists, OutflowTracker, and Output Validator.
- Fail-Closed Policy: Middleware strictly rejects pre-wrapped calldata and blocks calls when relayer is unreachable.
- All protected API routes enforce standard security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).


## 11) Backend endpoint index (port 8001)

Generated from the routers included in `backend/main.py`. `backend/routers/web3_security_routes.py` defines `/api/v1/web3/*` routes but is not included in the app, so those are not served.

**Agentic controls (grants, keys, policy edges)** (`backend/routers/agentic_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/agentic/config-snapshot` |
| GET | `/api/v1/agentic/grants` |
| POST | `/api/v1/agentic/grants` |
| POST | `/api/v1/agentic/grants/{execution_id}/revoke` |
| GET | `/api/v1/agentic/keys` |
| POST | `/api/v1/agentic/keys` |
| POST | `/api/v1/agentic/keys/{key_db_id}/rotate` |
| GET | `/api/v1/agentic/metrics` |
| GET | `/api/v1/agentic/policy-edges` |
| POST | `/api/v1/agentic/policy-edges` |
| POST | `/api/v1/agentic/revocations` |

**Audit badges** (`backend/routers/audit_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/audits` |
| GET | `/api/v1/audits/{badge_id}/svg` |
| POST | `/api/v1/verify-badge` |

**Auth & sessions** (`backend/routers/auth_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/auth/lockouts` |
| POST | `/api/v1/auth/lockouts/clear` |
| POST | `/api/v1/auth/login` |
| GET | `/api/v1/auth/revocations` |
| POST | `/api/v1/auth/revocations/prune` |
| POST | `/api/v1/auth/revoke` |
| GET | `/api/v1/auth/sessions` |
| POST | `/api/v1/auth/sessions/revoke-all` |
| POST | `/api/v1/auth/sessions/revoke-jti` |
| POST | `/api/v1/auth/sessions/revoke-self` |
| POST | `/api/v1/auth/sessions/revoke-self-jti` |
| POST | `/api/v1/auth/sessions/revoke-user` |
| POST | `/api/v1/auth/token` |
| GET | `/api/v1/auth/whoami` |
| POST | `/login` |
| GET | `/logout` |

**Billing & tenants** (`backend/routers/billing_routes.py`)

| Method | Path |
|---|---|
| DELETE | `/api/v1/admin/tenant-data` |
| POST | `/api/v1/billing/checkout` |
| POST | `/api/v1/billing/confirm` |
| GET | `/api/v1/customers` |
| GET | `/api/v1/orders` |
| GET | `/api/v1/public/plans` |

**Scan campaigns, schedules, vector packs** (`backend/routers/campaign_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/campaigns` |
| POST | `/api/v1/campaigns` |
| GET | `/api/v1/campaigns/{campaign_id}` |
| GET | `/api/v1/campaigns/{campaign_id}/report` |
| POST | `/api/v1/scan/verify` |
| GET | `/api/v1/schedules` |
| POST | `/api/v1/schedules` |
| GET | `/api/v1/schedules/history` |
| DELETE | `/api/v1/schedules/{schedule_id}` |
| GET | `/api/v1/vector-packs` |
| POST | `/api/v1/vector-packs/upload` |
| POST | `/api/v1/vector-packs/validate` |

**Smart-contract analysis** (`backend/routers/contract_routes.py`)

| Method | Path |
|---|---|
| POST | `/api/v1/contract/analyze` |
| POST | `/api/v1/contract/analyze/onchain` |
| GET | `/api/v1/contract/chains` |
| GET | `/api/v1/contract/rules` |

**Cortex memory, insurance, interlocks, risk attestations** (`backend/routers/cortex_routes.py`)

| Method | Path |
|---|---|
| POST | `/api/v1/cortex/anchor` |
| GET | `/api/v1/cortex/chains` |
| POST | `/api/v1/cortex/interlock` |
| POST | `/api/v1/cortex/record` |
| POST | `/api/v1/cortex/verify` |
| GET | `/api/v1/cortex/{agent_id}/anchors` |
| GET | `/api/v1/cortex/{agent_id}/chain/{event_id}` |
| GET | `/api/v1/cortex/{agent_id}/events` |
| GET | `/api/v1/cortex/{agent_id}/insurance` |
| GET | `/api/v1/cortex/{agent_id}/replay` |
| POST | `/api/v1/cortex/{agent_id}/start-trial` |
| GET | `/api/v1/cortex/{agent_id}/trial` |
| GET | `/api/v1/insurance/{agent_id}/certificates` |
| POST | `/api/v1/insurance/{certificate_id}/anchor` |
| POST | `/api/v1/interlock/{interlock_id}/anchor` |
| GET | `/api/v1/risk/{chain}/{address}/attest` |

**Dashboard & WebSocket** (`backend/routers/dashboard_routes.py`)

| Method | Path |
|---|---|
| GET | `/` |
| GET | `/site` |
| WS | `/ws/threats` |

**ERC-8004 identity** (`backend/routers/identity_registry_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/erc8004/agents/{agent_id}.json` |
| POST | `/api/v1/erc8004/register` |
| GET | `/api/v1/erc8004/status/{agent_id}` |

**Health, metrics, telemetry, API keys, audit log, compliance, RBAC** (`backend/routers/misc_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/analytics` |
| GET | `/api/v1/api-keys` |
| POST | `/api/v1/api-keys` |
| POST | `/api/v1/api-keys/{key_id}/revoke` |
| POST | `/api/v1/api-keys/{key_id}/rotate` |
| GET | `/api/v1/audit-log` |
| GET | `/api/v1/audit-log/failures` |
| POST | `/api/v1/audit-log/retry-failures` |
| GET | `/api/v1/audit-log/summary` |
| GET | `/api/v1/audit-log/verify` |
| GET | `/api/v1/compliance/report` |
| GET | `/api/v1/rbac/policy` |
| POST | `/api/v1/telemetry` |
| GET | `/health` |
| GET | `/metrics` |

**Passports, credentials, encrypted memory** (`backend/routers/passport_routes.py`)

| Method | Path |
|---|---|
| POST | `/api/v1/passport/issue` |
| GET | `/api/v1/passport/leaderboard` |
| POST | `/api/v1/passport/memory` |
| GET | `/api/v1/passport/memory/{agent_id}` |
| POST | `/api/v1/passport/memory/{agent_id}/tamper` |
| GET | `/api/v1/passport/public-key` |
| POST | `/api/v1/passport/verify` |
| GET | `/api/v1/passport/{agent_id}` |
| GET | `/api/v1/passport/{agent_id}/credentials` |
| POST | `/api/v1/passport/{agent_id}/credentials/issue` |
| POST | `/api/v1/passport/{agent_id}/revoke` |
| GET | `/api/v1/passport/{agent_id}/score` |

**Agent security scans** (`backend/routers/scan_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/leaderboard` |
| POST | `/api/v1/scan` |
| GET | `/api/v1/scan-history` |
| GET | `/api/v1/scan-jobs` |
| POST | `/api/v1/scan-jobs` |
| GET | `/api/v1/scan-jobs/{job_id}` |
| GET | `/api/v1/scan/compare` |
| GET | `/api/v1/scan/history` |
| GET | `/api/v1/scan/{scan_id}/pdf` |
| GET | `/api/v1/scan/{scan_id}/report` |
| GET | `/api/v1/scan/{scan_id}/sarif` |

**Events & exports** (`backend/routers/telemetry_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/events` |
| GET | `/api/v1/export/csv` |
| GET | `/api/v1/export/json` |

**Threat intelligence** (`backend/routers/threat_intel_routes.py`)

| Method | Path |
|---|---|
| GET | `/api/v1/threat-intel/incidents` |
| GET | `/api/v1/threat-intel/incidents/{incident_id}` |
| POST | `/api/v1/threat-intel/screen` |
| POST | `/api/v1/threat-intel/screen/batch` |
| GET | `/api/v1/threat-intel/stats` |
| POST | `/api/v1/threat-intel/sync` |

