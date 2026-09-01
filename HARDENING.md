# GuardianAI Security Hardening Guide

Follow these practices to secure your GuardianAI deployment against advanced threats.

## 1. Secret Management

### Do Not Hardcode
- Never store API keys or backend tokens in `config.yaml`.
- Use **Environment Variables** for all secrets.

### Supported Secrets
- `GUARDIAN_OPENROUTER_API_KEY`: For AI Firewall model calls.
- `GUARDIAN_BACKEND_TOKEN`: For authenticated telemetry reporting.

## 2. Network Security

### Ingress Filtering
- The Guardian Proxy should **NOT** be exposed directly to the public internet without a Load Balancer or WAF.
- Use TLS 1.3 for all incoming connections.

### Egress Filtering
- Limit Guardian Proxy egress to:
  - Valid downstream agent URLs.
  - Known AI provider APIs (e.g., `openrouter.ai`).
  - Community threat feed URLs.
  
  ### Base64 Evasion Prevention
  - Ensure `enable_base64_detection` is set to `true` (Segment 4 requirement).
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
- If Redis is unavailable, GuardianAI safely falls back to in-memory buckets (single-node mode).

## 4. Host Security

### Running as Non-Root
- Always run the Guardian processes as a dedicated `guardian` user with limited shell access.
- In Docker, use: `USER 1000:1000`.

### System Shield (Runtime Monitor)
- Keep `RuntimeMonitor` enabled to detect unauthorized process spawns or resource exhaustion attacks.

## 5. Regular Audits

### Pattern Updates
- Schedule a job to `POST /api/reload-model` weekly to ensure the latest jailbreak vectors are loaded into the AI Firewall.

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
- **Revocation & Rotation:** Refresh tokens rotate on every issue; revoked tokens are persisted and checked by unique `jti`.

## 8. Web Security Headers & Payload Controls

- **Security Headers:** All HTTP responses automatically include:
  - `Content-Security-Policy: default-src 'self'`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **CSRF Protection:** State-changing requests (`POST`, `PUT`, `DELETE`) require a valid `X-CSRF-Token` matching the secure cookie.
- **Body Limit:** Maximum request body size is capped at 1MB to prevent memory exhaustion / DoS attacks.
- **Fail-Closed Rate Limiter:** When Redis or rate-limiting infrastructure is degraded, the rate limiter fails closed (HTTP 503) rather than failing open.
- **WebSocket Auth:** Threat stream WebSocket requires authentication payload within the first 10 seconds and strictly validates admin/auditor roles.

## 9. Smart Contract Safety & Timelocks

- **Timelock Governance:** On-chain contract ownership is transferred to `GuardianTimelock.sol` with a mandatory 24-hour minimum execution delay (`MIN_DELAY = 24 hours`).
- **Certificate Capping:** `GuardianInsuranceLedger.sol` enforces `MAX_CERTIFICATES = 100,000` with custom error `CertificateLimitReached()` as the first line of execution.

## 10. Web3 Identity & Hot-Wallet Collision Defense

- **Active Wallet Uniqueness:** A database partial unique index (`ON agent_passports(owner_pubkey COLLATE NOCASE) WHERE is_active = 1`) strictly prevents multiple active AI agents from multiplexing the same hot wallet address.
- **Deterministic Resolver Tiebreaking:** `IdentityGate` resolves addresses using active-first `ORDER BY is_active DESC, updated_at DESC` across passports and ERC-8004 registrations, preventing revoked graveyard records from hijacking permissions or causing false-positive blocks.
- **Fail-Safe RPC Resiliency:** Configured to fail-open (`GUARDIAN_IDENTITY_GATE_FAIL_CLOSED=false`) during network/RPC interruptions, maintaining agent uptime while logging full on-chain error telemetry.
- **Shadow Mode Staging:** Deploy in `GUARDIAN_IDENTITY_GATE_MODE=shadow` initially. Verify 0 drift via `python audit_identity_drift.py` before promoting to `enforce` mode.





