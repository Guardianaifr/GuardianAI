# GuardianAI Operations Guide

This document outlines the operational procedures for maintaining a healthy GuardianAI deployment.

## 1. State Management & Resource Limits

### Multi-turn Context Buffer
- **Component**: `GuardianProxy`
- **Behavior**: Stores the last 5 prompts per session ID (or IP) for semantic analysis.
- **Limit**: 5 prompts per session.
- **Cleanup**: Currently, state persists in memory until process restart. In high-traffic environments, monitor memory usage of the `guardian_proxy` process.
- **Recommendation**: For production, use a redis-backed session store if persistence across restarts or multi-instance sync is required.

### Rate Limiter Buckets
- **Component**: `RateLimiter`
- **Behavior**: Uses a Token Bucket algorithm per IP in memory.
- **Cleanup**: In-memory dictionary grows with unique IPs.
- **Recommendation**: Periodic restarts or migration to a distributed rate limiter (Redis) for large-scale deployments.

## 2. Log Management & Archival

### Log Locations
- **Standard Out**: Logs are emitted to STDOUT/STDERR.
- **Log Files**: In production (Docker/Systemd), logs are managed by the host system (e.g., `journalctl` or Docker log driver).

### Maintenance (Cleanup)
- **Rotation**: Ensure log rotation is configured (e.g., via `logrotate` on Linux).
- **Retention**: Keep security logs for a compliance-appropriate retention window.

## 3. Backup & Restore Procedures

### Configuration Backup
The most critical state in GuardianAI is the `guardian/config/` files and environment variables.
- **Backup Command**:
  ```bash
  tar -czvf guardian_config_backup_$(date +%F).tar.gz ./config/
  ```
- **Frequency**: Backup after any configuration change.

### Threat Feed Persistence
Threat feeds are updated dynamically in memory.
- **Restore**: On restart, GuardianAI will automatically fetch the latest community patterns from the configured URL.

### Telemetry Data
If using the Guardian Dashboard/Backend:
- **Database**: Ensure the backend database (SQLite (default)) has an automated backup schedule (e.g., `sqlite3 guardian.db '.backup ...'` on a cron, or litestream).

## 4. Monitoring & Alerts

### Health Checks
- **Endpoint**: `GET /health`
- **Threshold**: Response code 200 within 500ms.

### Metric Thresholds
- **CPU**: Alert if > 80% for 5 mins.
- **Memory**: Alert if > 2GB (for small deployments).
- **Latency (p95)**: Alert if > 100ms.



## ERC-8004 Identity Registration Runbook (added 2026-08-23)

**Status:** disabled by default. Nothing runs unless `GUARDIAN_ERC8004_ENABLED=true`.

### Enablement checklist (in order)
1. Set `GUARDIAN_ERC8004_CHAINS` (rollout order: `base-sepolia` → `base` → `monad-testnet`).
2. Provision a **dedicated** `GUARDIAN_ERC8004_REGISTRAR_KEY` (never reuse the deployer key). Fund it for gas.
3. Set `GUARDIAN_PUBLIC_URL` to the production `https://` endpoint — on mainnet chains the registrar refuses localhost/plain-http URLs (fail-closed).
4. Optionally set `GUARDIAN_ERC8004_DAILY_BUDGET_WEI` (recommended for mainnet; `0` = uncapped).
5. Flip `GUARDIAN_ERC8004_ENABLED=true` and restart the backend.

### Known operational behaviors
- **Full pytest suite:** 3 tests fail only under full-suite ordering and pass individually (state isolation issue, tracked). Verify with targeted runs before treating as regressions.
- **Analyzer fixture suite must run standalone:** `pytest tests/audit/test_smart_contract_analyzer.py --no-cov`. Under coverage instrumentation Slither silently falls back to regex detection — green results, weaker detector actually exercised.
- **Registration worker:** daemon thread, poll interval `GUARDIAN_ERC8004_POLL_SECONDS` (default 30s), retries capped at `GUARDIAN_ERC8004_MAX_RETRIES` (default 5).
- **Row states:** `pending → registering → metadata → confirmed`, failures land in `failed` with `last_error`. Admin `POST /api/v1/erc8004/register` re-invocation resets only FAILED rows.
- **Ownership handoff:** supply `owner_address` at registration; sequence is register → setMetadata → transferFrom. Transfer is skipped automatically if `ownerOf()` already shows client ownership (idempotent retry after receipt-timeout).
- **Before mainnet:** validate the ABI subset in `erc8004_registrar.py` against the pinned audited release of `erc8004/erc-8004-contracts`; decide identity custody per the register-then-transfer policy (whitepaper Feature 39).

### Canonical registry availability (verified 2026-08-23)
`eth_getCode` probes: canonical `0x8004A169…a432` is deployed on **Base mainnet and Polygon mainnet** but has **no bytecode on Base Sepolia or Ethereum Sepolia**. For testnet rehearsal, deploy the stand-in (`contracts/contracts/erc8004/IdentityRegistryTestnet.sol`, ABI-faithful, NOT the audited reference) via `npx hardhat run scripts/deploy-erc8004-testnet.ts --network base_sepolia` and set `GUARDIAN_ERC8004_IDENTITY_REGISTRY_OVERRIDE`. The registrar's fail-closed gate will refuse any chain where the target registry has no bytecode.
