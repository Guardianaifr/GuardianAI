# GuardianAI Validation & Verification Guide

This document outlines how we validate the security, performance, and reliability of GuardianAI.

## Current Test Status
- **Total Tests (October 2026, README test table):** Python 1,490+; Hardhat 271; Mera 26 Vitest + 166 hard-audit assertions; Envio indexer 48; agent middleware 49 + 15; hosted ElizaOS agent 10; explorer 52
- **Key Coverage:** Authentication, PII Redaction, Adversarial Defense, Audit Logging, RBAC, relay attestations, agent wallets, CRE threat feed, passkey agent cards

## Verification Layers

### 1. Unit Tests (`tests/`)
Comprehensive test suite covering individual components.
Run all tests:
```bash
python -m pytest tests/
```

Key Test Files:
- `tests/test_auth_proxy.py`: Verifies JWT/API Key enforcement.
- `tests/test_extended_security.py`: Verifies sophisticated defenses (Base64, Skill Scanner).
- `tests/test_audit_logging.py`: Verifies external log sinks (Splunk, Datadog).
- `tests/verify_ssrf.py`: Special probe for Server-Side Request Forgery.

Relay and on-chain path:
- `tests/test_rpc_relay.py`, `tests/test_attestation_service.py`: relay and EIP-712 signing.
- `tests/test_agent_wallet_attestation.py`: approvals bound to a `GuardianAgentWallet`.
- `tests/test_threat_oracle_feed.py`: the deterministic feed read by Chainlink CRE.
- `tests/test_agent_card.py`: Mera passkey-signed agent cards.
- `tests/test_cloud_relay.py`: the public relay's route guard and rate limits.

### Other suites

| Suite | Command |
|---|---|
| Smart contracts | `cd contracts && npx hardhat test` |
| Mera passkey | `cd metropolis/mera && npm test && npm run test:hard` |
| Envio indexer | `cd metropolis/indexer && npm test` |
| Agent middleware | `cd packages/guardian-middleware && npm test` |
| Hosted ElizaOS agent | `cd packages/eliza-host && npm test` |
| Explorer / console | `cd dashboard && npm test` |

### 2. Hardening Demos ("The Gauntlet")
A suite of 10 live-fire scenarios running against a real backend instance.
Run directly via `pytest tools/hardening_demos.py` against a locally started backend (`python guardianctl.py start`).

| Demo ID | Feature Tested | Outcome |
| :--- | :--- | :--- |
| 1 | Security Posture | Health checks, HTTPS enforcement |
| 2 | Identity & RBAC | Token issuance, role enforcement |
| 3 | Session Inventory | Active session tracking |
| 4/5 | Revocation | Self-revocation, JTI blacklisting |
| 6 | Lockout | Brute-force protection |
| 7 | Admin Containment | Privilege escalation prevention |
| 8 | API Keys | Lifecycle management |
| 9 | Audit Integrity | Tamper-evident hash chain |

### 3. Real-Time Verification
Attack simulations (see `demo/full_demo.py`, scenes 2–3) verify:
- Prompt Injection blocking
- PII Redaction coverage
- Rate Limiting

## Performance Benchmarks
Run the professional benchmark suite:
```bash
.\.venv312\Scripts\python.exe tools/run_performance_chaos_validation.py
```
**Target Metrics:**
- Latency (p95): < 20ms (internal overhead)
- Throughput: > 1000 req/sec (on standard hardware)

## Continuous Validation
We recommend running the full test suite (`pytest`) before every deployment and the hardening demos after every major configuration change.
