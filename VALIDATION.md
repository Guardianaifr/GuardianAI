# GuardianAI Validation & Verification Guide

This document outlines how we validate the security, performance, and reliability of GuardianAI.

## Current Test Status
- **Total Tests:** backend + unit suites: 172 passed (2026-08-25)
- **Key Coverage:** Authentication, PII Redaction, Adversarial Defense, Audit Logging, RBAC

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
Attack simulations (see `demo/full_demo.py`, Scene 2–3) verify:
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
