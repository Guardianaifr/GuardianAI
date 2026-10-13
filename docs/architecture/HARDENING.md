# GuardianAI Security Hardening Guide

Follow these practices to secure your GuardianAI deployment against advanced threats.

## 1. Secret Management

### Do Not Hardcode
- Never store API keys or backend tokens in `config.yaml`.
- Use **Environment Variables** for all secrets.

### Main secrets (see `.env.example`)
- `GUARDIAN_ADMIN_PASS`, `GUARDIAN_JWT_SECRET`: admin login and JWT signing.
- `GUARDIAN_BACKEND_TOKEN`: authenticated telemetry from the proxy/runtime to the backend.
- `GUARDIAN_ATTESTATION_SIGNER_KEY`: relay key that signs EIP-712 approvals. Must differ from the deployer key; the relay refuses to start in production otherwise.
- `GUARDIAN_DEPLOYER_PRIVATE_KEY`, `GUARDIAN_ERC8004_REGISTRAR_KEY`: on-chain deployment and identity registration (keep them separate, never on the public relay).
- `GUARDIAN_VC_PRIVATE_KEY`: signs passport Verifiable Credentials.
- `PRIVY_APP_SECRET`: Privy server-wallet agent (`tools/privy-agent`); can be kept in the Mera vault instead of `.env`.

## 2. Network Security

### Ingress Filtering
- The Guardian Proxy should **NOT** be exposed directly to the public internet without a Load Balancer or WAF.
- Use TLS 1.3 for all incoming connections.

### Egress Filtering
- Limit Guardian Proxy egress to:
  - Valid downstream agent URLs.
  - Known AI provider APIs used by your upstream.
  - Community threat feed URLs.

### Base64 Evasion Prevention
- Ensure `enable_base64_detection` is set to `true`.
  - This blocks obfuscated payloads with high entropy (potential command-and-control communication).

## 3. Defensive Configuration (config.yaml)

### Security Mode
- **Strict**: Recommended for financial or healthcare applications. Blocks on any ambiguity.
- **Balanced**: Best for general productivity. Minimal false positives.

### Data Leak Prevention
- Ensure `leak_prevention_strategy` is set to `block` in high-security environments.
- Use `redact` only for development or non-critical paths.

### Distributed Rate Limiting (SaaS)
- For multi-instance deployments, configure Redis-backed token buckets:
  - `rate_limiting.redis_url`
  - `rate_limiting.redis_prefix`
- Outside production, if Redis is unavailable the limiter falls back to in-memory buckets (single-node mode). With `GUARDIAN_ENV=production` the backend refuses to start without the Redis backend, and Redis errors fail closed (HTTP 503).

## 4. Host Security

### Running as Non-Root
- Always run the Guardian processes as a dedicated `guardian` user with limited shell access.
- In Docker, use: `USER 1000:1000`.

### System Shield (Runtime Monitor)
- Keep `RuntimeMonitor` enabled to detect unauthorized process spawns or resource exhaustion attacks.

## 5. Regular Audits

### Pattern Updates
- Schedule a job to `POST /api/reload-model` on the proxy (admin token) weekly to ensure the latest jailbreak vectors are loaded into the AI Firewall.

### Dependency Scanning
- Run `pip-audit` monthly to check for CVEs in libraries like `transformers`, `torch`, or `flask`.

## 6. Policy Governance

- Enable governance gate in `config.yaml`:
  - `governance.enabled: true`
  - `governance.mode: enforce` (or `audit`)
  - `governance.policy_file: config/policy_control.yaml`
- High-risk config relaxations (for example `security_mode: lenient`) require approval metadata:
  - `approval.status: approved`
  - `approval.approver`
  - `approval.ticket`
  - `approval.config_sha256` (integrity pin of the exact config file)
- In `enforce` mode, startup is blocked when policy checks fail.

## 7. Authentication & JWT Hardening

- **Password Hashing:** Passwords must be hashed using Argon2id (`time_cost=7, memory_cost=65536, parallelism=4`). In production (`GUARDIAN_ENV=production`), legacy fallback to SHA-256 is strictly refused and triggers a startup halt.
- **JWT Secret Entropy:** Ensure `GUARDIAN_JWT_SECRET` contains high entropy (minimum 256 bits).
- **Token Validation:** Token decoder strictly enforces `alg: HS256` before signature parsing, constant-time HMAC comparison, expiration (`exp`), not-before (`nbf`), and expected audience (`aud`).
- **Revocation:** Revoked tokens are persisted and checked by unique `jti` (see the session endpoints in `API.md`). Refresh-token rotation exists in `backend/auth.py` but is not exposed by an HTTP route yet.

## 8. Web Security Headers & Payload Controls

- **Security Headers:** All HTTP responses automatically include:
  - `Content-Security-Policy: default-src 'self'`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **CSRF Protection:** State-changing requests (`POST`, `PUT`, `DELETE`) require a valid `X-CSRF-Token` matching the secure cookie.
- **Body Limit:** Maximum request body size is capped at 1MB to prevent memory exhaustion / DoS attacks.
- **Fail-Closed Rate Limiter (production):** When Redis is degraded in production, the rate limiter fails closed (HTTP 503) rather than failing open.
- **WebSocket Auth:** Threat stream WebSocket requires authentication payload within the first 10 seconds and strictly validates admin/auditor roles.

## 9. Smart Contract Safety & Timelocks

- **Timelock Governance:** `GuardianTimelock.sol` enforces a 24-hour minimum execution delay (`MIN_DELAY = 24 hours`) and is deployed on Monad testnet. Ownership of the deployed suite has **not** been transferred to it yet (still the deployer EOA); `contracts/scripts/transfer_ownership_to_timelock.js` does the handoff.
- **Certificate Capping:** `GuardianInsuranceLedger.sol` enforces `MAX_CERTIFICATES = 100,000` with custom error `CertificateLimitReached()` as the first line of execution.

## 10. Web3 Identity & Hot-Wallet Collision Defense

- **Active Wallet Uniqueness:** A database partial unique index (`ON agent_passports(owner_pubkey COLLATE NOCASE) WHERE is_active = 1`) strictly prevents multiple active AI agents from multiplexing the same hot wallet address.
- **Deterministic Resolver Tiebreaking:** `IdentityGate` resolves addresses using active-first `ORDER BY is_active DESC, updated_at DESC` across passports and ERC-8004 registrations, preventing revoked graveyard records from hijacking permissions or causing false-positive blocks.
- **Fail-Safe RPC Resiliency:** Configured to fail-open (`GUARDIAN_IDENTITY_GATE_FAIL_CLOSED=false`) during network/RPC interruptions, maintaining agent uptime while logging full on-chain error telemetry.
- **Shadow Mode Staging:** Deploy in `GUARDIAN_IDENTITY_GATE_MODE=shadow` initially and review the logged verdicts before promoting to `enforce` mode. (The former `audit_identity_drift.py` reconciliation script was removed on 2026-09-24.)

## 11. Cryptographic Tree Integrity & Second-Preimage Defense

- **RFC 6962 Domain Separation:** Internal Merkle tree parent nodes are hashed with a `0x01` domain separation byte (`SHA256(0x01 || left || right)`), strictly preventing second-preimage collision attacks between leaves and internal tree nodes.
- **Odd-Node Trailing Leaf Promotion (CVE-2012-2459 Fix):** Trees never pad odd-length node lists by duplicating the last element. Instead, odd trailing nodes are promoted directly to the next level bottom-up, preventing malleability attacks where `[A, B, C]` and `[A, B, C, C]` produce identical roots.

## 12. Gateway Smuggling & Payload Defenses

- **RFC 9110 Hop-by-Hop Header Stripping:** Before forwarding HTTP requests to upstream LLMs, `GuardianProxy` unconditionally strips all RFC 9110 hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`, `Host`, and `Content-Length`) to prevent HTTP request smuggling and framing desynchronization.
- **Request Entity Ceiling (10MB):** Configured with `MAX_CONTENT_LENGTH = 10 * 1024 * 1024` and a JSON 413 error handler to block unbounded payload buffer allocations and memory-exhaustion denial-of-service attacks.
- **Streaming SSE OWASP LLM07 Inspection:** Server-Sent Events (SSE) token chunks are parsed in real time to accumulate complete textual deltas, actively evaluated against `SystemPromptGuard` to block prompt leakages in streaming responses.

## 13. Concurrency & Distributed Rate Limiting

- **Atomic Redis Lua Token Bucket:** Token bucket calculations, replenishment rates, and recovery deductions are executed inside an atomic Redis Lua script (`_REDIS_RATE_LIMIT_LUA`), eliminating check-then-act race conditions during concurrent request bursts.
- **Bounded Local Buckets & Background Janitor:** In-memory buckets are capped at `max_local_buckets = 50,000`. A dedicated daemon thread (`RateLimiterJanitor`) runs every 60 seconds to prune stale IP buckets and purge sliding burst-window timestamps, preventing long-running monotonic memory leaks.

## 14. Differential Privacy & Cryptographic Secrets

- **Discrete Geometric Mechanism:** Implements a two-sided geometric mechanism (`geometric_noise`) for discrete count differential privacy, alongside un-clamped continuous noise (`noisy_count_unbiased`) to eliminate the positive truncation bias created by zero-clamping (`max(0, ...)`).
- **Keystream Deprecation:** Legacy unauthenticated XOR stream cipher secrets without nonces are strictly prohibited and rejected at startup/runtime when `GUARDIAN_ENV=production`. AES-256-GCM with authenticated 96-bit nonces (`v2:`) is mandatory.

## 15. Agent Wallets, Relay Signer & Passkey Identity (October 2026)

- **Two keys per payment:** New agents should hold funds in a `GuardianAgentWallet`. `execute` needs the agent's own key (`msg.sender == operator`) **and** a fresh GuardianAI EIP-712 attestation bound to that wallet, so neither a leaked agent key nor a leaked relay signer can move funds alone. The owner's `ownerExecute` is the recovery path and bypasses GuardianAI by design; in production the owner should be a passkey, multisig or the timelock.
- **On-chain scam list:** Set the wallet's threat oracle to `GuardianThreatOracle`; it only accepts reports from the Chainlink Forwarder, and the wallet refuses flagged targets, recipients and spenders.
- **Relay signer:** Keep `GUARDIAN_ATTESTATION_SIGNER_KEY` separate from the deployer key (the relay refuses to start in production if they match) and rotate with `tools/rotate_attestation_signer.py`. It is still a single hot key; KMS/HSM or threshold signing is the next step.
- **Shared-spender pulls:** `transferFrom` pulls through PolicyGuard need an EIP-712 authorization signed by the asset owner (single use, at most 10 minutes). The replay cache is per relay process, so run one relay instance or move the cache to Redis.
- **Passkey-bound agents:** List agents in `config/agent_passkey_identities.json` to require a Mera passkey-signed agent card on every `/api/v1/attest` call. Unlisted agents' `agent_id` is still caller-supplied.
- **Privy policy:** Run the Privy agent's key as a policy-locked server wallet (`tools/privy-agent/policy.cjs`) and re-check with `node agent.cjs lock-test`.
