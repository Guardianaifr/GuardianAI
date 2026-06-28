---
name: guardian-phase1-argon2-jwt
description: >-
  Replaces SHA-256 password hashing with Argon2id in auth.py, hardens JWT 
  (removes hardcoded secrets, adds aud/nbf validation), consolidates JWT 
  to auth.py, and updates Dockerfile and requirements.txt.
---

# Guardian Phase 1: Argon2 & JWT Hardening

## Overview
This skill implements Phase 1 of the GuardianAI Security Audit Remediation. It secures the authentication and authorization layer by upgrading the password hashing algorithm and securing JWT management.

## Workflow

### 1. Replace SHA-256 with Argon2id
- **Target File:** `auth.py`
- Replace `hash_password()` and `verify_password()` with `argon2-cffi` (argon2id variant).
- Add backward compatibility to fallback to legacy SHA-256 verification (using `hmac.compare_digest`) for existing hashes.
- Implement a `needs_rehash()` function to detect legacy hashes for seamless upgrades.

### 2. Harden JWT and Consolidate Logic
- **Target Files:** `auth.py`, `main.py`
- Consolidate all JWT logic into a single source of truth in `auth.py`.
- Remove hardcoded default credentials and JWT secrets.
- Add `aud` (audience) and `nbf` (not before) claim validation.

### 3. Update Dependencies and Docker Configuration
- **Target File:** `requirements.txt`
  - Add `argon2-cffi==23.1.0`.
- **Target File:** `Dockerfile`
  - Add `ENV GUARDIAN_ENV=production`.

## Acceptance Criteria
- `grep -i sha256 auth.py` shows only the legacy fallback block.
- `pytest tests/ -v --ignore=tests/backend/test_billing_checkout.py --ignore=tests/backend/test_customer_billing_storage.py` passes with 0 failures.
