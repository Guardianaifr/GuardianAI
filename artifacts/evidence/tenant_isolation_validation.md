# Tenant Isolation Validation Report

Date: March 11, 2026
Status: Completed

## Objective

Verify tenant-scoped isolation controls across:

- session and behavior tracking
- telemetry persistence and retrieval
- evidence storage

## Implemented Controls

1. Tenant-scoped session isolation

- Added tenant resolution and validation (`X-Guardian-Tenant` configurable header).
- Added optional strict mode requiring tenant header.
- Session IDs are tenant-scoped when enabled (`tenant:<tenant_id>:<session_id>`), isolating blue-team/adaptive state and cost-abuse tracking by tenant.

2. Tenant-scoped telemetry isolation

- Telemetry payload now includes `tenant_id`.
- Backend storage schema supports `tenant_id` on `security_events` and `analytics`.
- Backend endpoints support tenant-scoped retrieval:
  - `/api/v1/events?tenant_id=...`
  - `/api/v1/analytics?tenant_id=...`
  - `/api/v1/export/json?tenant_id=...`
  - `/api/v1/export/csv?tenant_id=...`

3. Tenant-scoped evidence isolation

- Added per-tenant JSONL evidence sink:
  - `artifacts/evidence/tenants/<tenant_id>/events.jsonl`
- Evidence writes happen for reported events even when backend telemetry forwarding is disabled.

## Validation Scenarios

1. Required tenant header enforcement

- With tenant isolation enabled and header required:
  - Missing tenant header returns `400`.

2. Tenant data segregation in backend

- Telemetry ingested for `tenant-a` and `tenant-b`.
- Querying events by tenant returns only matching tenant rows.
- Tenant-scoped analytics counts only selected tenant records.

3. Tenant evidence segregation

- Event reported with tenant `acme` writes under:
  - `artifacts/evidence/tenants/acme/events.jsonl`

## Verification Evidence

Commands and outcomes:

- `pytest -q tests/runtime/test_interceptor.py` -> `32 passed`
- `pytest -q tests/backend/test_unauthorized_access.py tests/backend/test_tenant_isolation_backend.py` -> `7 passed`
- `pytest -q` -> `179 passed`
- `python tools/run_missing_security_validation.py` -> passed (`sast_findings: 0`)
- `python tools/run_hardening_validation.py` -> completed (expected fixture findings present)
- `python tools/run_performance_chaos_validation.py` -> passed
- `python tools/check_security_slo.py` -> passed (`all_passed: true`)

## Conclusion

Tenant-scoped session, telemetry, and evidence segregation controls are implemented and test-verified with no observed cross-tenant leakage in automated coverage.
