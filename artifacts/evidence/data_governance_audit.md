# Data Governance Audit Report — Phase 4 Update

- **Run timestamp**: 2026-04-20 14:00:00 UTC
- **DB path**: `guardian.db`
- **Retention policy (days)**: `30`
- **Observed tenant count**: `1+` (multi-tenant capable)
- **Stale records older than retention**: `0`
- **Retention policy pass**: `True`

## Data Governance Controls

| Control | Status | Evidence |
|---------|--------|----------|
| 30-day auto-purge on ingest | ✅ | `backend/main.py` line 557: `retention_cutoff` enforced |
| Tenant-scoped data isolation | ✅ | All queries filter by `tenant_id`, RBAC enforces scoping |
| PII redaction at proxy layer | ✅ | Presidio-based entity detection (12+ types) |
| Differential privacy for analytics | ✅ | Laplace mechanism, configurable epsilon |
| Immutable audit logs | ✅ | SHA-256 signed audit entries for admin actions |
| RBAC-gated data access | ✅ | 4 roles, tenant-scoped read_only and tenant_admin |

## Auth & Access Control

| Control | Status |
|---------|--------|
| JWT-based authentication | ✅ Active (HS256, 30-min access tokens) |
| Refresh token rotation | ✅ Old refresh tokens revoked on use |
| Token revocation list | ✅ SQLite-backed, survives restart |
| Admin auto-bootstrap | ✅ First admin user created on startup |
| Password hashing | ✅ Argon2id (time_cost=7, memory_cost=64MB, parallelism=4) with legacy SHA-256 migration |

## EU AI Act Data Requirements

| Article | Requirement | Status |
|---------|-------------|--------|
| Art. 10 | Data governance documentation | ✅ This document |
| Art. 12 | Automatic event logging | ✅ All proxy events logged |
| Art. 17 | Quality management records | ✅ 407 tests, CI-ready |
