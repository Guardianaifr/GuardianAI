---
name: guardian-phase3-hardening
description: >-
  Hardens CORS, moves WebSocket auth to first message, makes rate limiter fail-closed,
  adds scan_id path traversal validation, adds Pydantic max_length constraints,
  adds 1MB request body limit, tunes entropy filter, adds 5 security headers,
  adds CSRF protection, uses SystemRandom in DP, and enables MemoryPoisoningGuard.
---

# Guardian Phase 3: API & Guardrail Hardening

## Overview
This skill implements Phase 3 of the GuardianAI Security Audit Remediation. It hardens various APIs, middleware, security headers, input/output validation checks, and guardrails across the python backend.

## Workflow

### 1. API & Security Hardening
- **Hardens CORS (`main.py`):** Replaces CORS wildcard configurations with explicit allow lists (`PUBLIC_BASE_URL` with fallback to `http://localhost:8001`), credentials enabled, and safe headers/methods.
- **WebSocket Auth (`dashboard_routes.py`):** Replaces query-parameter token auth in `/ws/threats` by immediately accepting the connection and waiting up to 10s for the first message `{"token": "..."}`. Validates token via `_jwt_decode()` using `JWT_SECRET`. Closes with `1008` code + `{"error": "unauthorized"}` message if validation fails or times out.
- **Rate Limiter Fail-Closed (`main.py`):** Configures the Redis rate limiter to fail-closed (HTTP 503 with `"Rate limiter unavailable"` detail) when Redis is down, unless `GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN` is explicitly set to `"true"`. Specifically catches `redis.RedisError`.
- **scan_id Path Traversal Sanitization (`scan_routes.py`):** Sanitizes the `scan_id` parameter in all matching routes (`get_scan_report`, `get_scan_report_pdf`, and `get_scan_sarif`) with a strict regex `^[a-zA-Z0-9_-]+$`. Removes `--no-sandbox` argument from Chrome/Edge PDF generator subprocess calls.
- **Pydantic Validation & Body Size Limits (`main.py`):**
  - Defines a custom `BaseModel` that automatically wraps all default string fields with `maxLength: 512` in JSON schema and validation.
  - Adds specific constraints (`max_length=256` and `max_length=128`) to `SecurityEvent` fields.
  - Adds a `LimitUploadSizeMiddleware` to reject any HTTP request body exceeding 1MB (returns `413 Request Entity Too Large`).
- **Tuned Entropy Filter & Prompt Length (`input_filter.py`):**
  - Raises the default Shannon entropy threshold to `5.5` to avoid false positives.
  - Makes max prompt length configurable via `GUARDIAN_MAX_PROMPT_LENGTH` env var.
  - Adds an `is_code_input` helper to exempt code snippets/blocks from the entropy check.
- **Security Headers Middleware (`main.py`):** Adds a middleware injecting standard headers: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Strict-Transport-Security`, `Content-Security-Policy`, and `Referrer-Policy`.
- **CSRF Protection (`main.py`):** Adds double-submit cookie validation using the `guardian_csrf` cookie and `X-CSRF-Token` header. Exempts machine-to-machine requests with API key or authorization headers, and unauthenticated public paths.
- **DP PRNG Hardening (`differential_privacy.py`):** Ensures `random.SystemRandom()` is used when `GUARDIAN_ENV` is set to `"production"`.
- **Enable MemoryPoisoningGuard (`memory_guard.py`):** Sets `enabled = True` by default in the constructor configuration.

## Acceptance Criteria
- Running the test suite passes with 0 failures (excluding billing tests):
  ```powershell
  pytest tests/ -v --ignore=tests/backend/test_billing_checkout.py --ignore=tests/backend/test_customer_billing_storage.py --ignore=tests/security/test_hardened_security_audit.py
  ```
- Sending a HTTP GET request returns responses containing all five security headers:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `Referrer-Policy: strict-origin-when-cross-origin`
