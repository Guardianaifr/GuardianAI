# GuardianAI Validation & Verification Guide

This document outlines how we validate the security, performance, and reliability of GuardianAI.

## Current Test Status
- **Total Tests:** 150
- **Key Coverage:** Authentication, PII Redaction, Adversarial Defense, Audit Logging, RBAC
- **Status:** PASSING (as of v1.0 Release)

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
Located in `tools/hardening_demos.py` and orchestrated via `demo_hardening_*.bat`.

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
Simulated attacks using `demo_realtime_*.bat` scripts to verify:
- Prompt Injection blocking
- PII Redaction coverage
- Rate Limiting

## Performance Benchmarks
Run the professional benchmark suite:
```bash
python professional_benchmark.py
```
**Target Metrics:**
- Latency (p95): < 20ms (internal overhead)
- Throughput: > 1000 req/sec (on standard hardware)

## Continuous Validation
We recommend running the full test suite (`pytest`) before every deployment and the hardening demos after every major configuration change.
