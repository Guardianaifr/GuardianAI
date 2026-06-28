---
name: guardian-phase2-refactor
description: >-
  Consolidates route handlers from main.py to router modules, reduces main.py size,
  fixes 22 test failures due to dual route registration, resolves import patch targets,
  and aligns shared state consistency across routers.
---

# Guardian Phase 2: Route Refactoring and State Consolidation

## Overview
This skill implements Phase 2 of the GuardianAI Security Audit Remediation. It trims the oversized `backend/main.py` by extracting route handlers into modular router files, resolves route conflicts/failures, aligns shared state globally, and fixes test failures.

## Workflow

### 1. Refactor Route Handlers
- **Target File:** `backend/main.py`
  - Remove all duplicate `@app.get`, `@app.post`, `@app.put`, and `@app.delete` route decorators and their handler functions.
  - Keep only: app creation, middleware definitions, database initialization, auth utilities, rate limiting logic, SIEM configs, global state, and router inclusions.
  - Reduce total lines in `backend/main.py` to 800–1,000 lines.
- **Target Directory:** `backend/routers/`
  - Ensure all extracted routes are cleanly registered to their respective `APIRouter` objects (e.g. `auth_routes`, `telemetry_routes`, `audit_routes`, `compliance_routes`).

### 2. Ensure Shared State and Router Consistency
- **Target Files:** `backend/routers/*`
  - Ensure shared constants and variables like `DB_PATH`, `JWT_SECRET`, and `ADMIN_PASS` are cleanly imported and resolved from `backend.main`.
  - Use dynamic global context synchronization if needed, or propagate configuration values dynamically when modified.
- **Target File:** `tests/backend/conftest.py`
  - Implement a synchronized monkeypatch decorator (`synced_setattr`) using `original_setattr` to intercept test mocks on `backend.main` variables and propagate them dynamically to all router modules. This prevents state pollution across tests and ensures cleanup at the end of each test execution.

### 3. Verification and Hardening Checks
- **Target File:** `backend/main.py`
  - Harden the compliance report function `_build_compliance_report()` to fail check evaluations (`fail`) if default credentials (`"guardian_default"`) or default secrets (`"guardian_jwt_dev_secret_change_me"`) are detected.

## Acceptance Criteria
- `wc -l backend/main.py` (or equivalent line count check) returns between 800 and 1,000 lines.
- No duplicate route decorators remain in `backend/main.py`.
- Running the test suite passes with 0 failures (excluding billing tests):
  ```powershell
  pytest tests/ -v --ignore=tests/backend/test_billing_checkout.py --ignore=tests/backend/test_customer_billing_storage.py --ignore=tests/security/test_hardened_security_audit.py
  ```
