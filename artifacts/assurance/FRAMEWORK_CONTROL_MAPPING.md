# Framework Control Mapping

Date: 2026-03-18
Scope: High-level mapping of implemented controls to common customer assurance frameworks.

Note: This document is an engineering/evidence mapping aid and not legal certification advice.

## SOC 2 (Trust Services Criteria) - Practical Mapping

| SOC 2 Area | GuardianAI Control Mapping | Evidence |
| --- | --- | --- |
| Security | Prompt injection prevention, semantic firewall, tool policy, authz controls | `END_TO_END_PROJECT_DOCUMENTATION.md`, `tests/runtime/test_interceptor.py` |
| Availability | Rate limiting, chaos validation, DR validation workflow | `artifacts/performance/perf_chaos_report.json`, `artifacts/evidence/dr_validation.md` |
| Confidentiality | Output leak detection/redaction, watermarking, model governance | `guardian/runtime/interceptor.py`, `artifacts/evidence/security_signoff.md` |
| Processing Integrity | Output assurance schema/citation/confidence gates | `guardian/security/output_assurance.py`, `tests/security/test_output_assurance.py` |
| Change Governance | Governance gate enforce/audit, signed evidence and release validation | `guardian/security/policy_governance.py`, `artifacts/evidence/compliance_bundle.json` |

## HIPAA Safeguard-Oriented Mapping (For BAA Discussions)

| HIPAA Safeguard Class | GuardianAI Control Mapping | Evidence |
| --- | --- | --- |
| Administrative | Incident drill process, policy governance, signoff workflow | `artifacts/evidence/incident_drill_report.md`, `artifacts/evidence/security_signoff.md` |
| Technical | Access controls, telemetry auth, tenant isolation, leak prevention | `tests/backend/test_unauthorized_access.py`, `tests/backend/test_tenant_isolation_backend.py` |
| Integrity | Output watermark signature verification, supply-chain artifact verification | `tools/verify_output_watermark.py`, `tools/verify_release_artifacts.py` |
| Availability | DR restore validation and SLO/chaos resilience checks | `artifacts/evidence/sre_slo_dr_signoff.md`, `artifacts/performance/perf_chaos_report.json` |

## GDPR / EU AI Act (Documentation-Oriented Mapping)

| Buyer Concern | GuardianAI Positioning | Evidence |
| --- | --- | --- |
| Data minimization and governance | Tenant-scoped handling and deletion controls | `tools/run_data_governance_audit.py`, `tests/backend/test_tenant_isolation_backend.py` |
| Automated decision transparency | Output assurance + false-negative taxonomy for residual risk framing | `artifacts/evidence/FALSE_NEGATIVE_TAXONOMY.md` |
| Technical/organizational safeguards | Defense-in-depth controls, benchmark alignment, event auditability | `FEATURE_BENCHMARK_ANALYSIS.md`, `artifacts/evidence/compliance_bundle.json` |
| Risk management lifecycle | Quarterly threat model cadence and external review metadata | `artifacts/evidence/threat_model_quarterly.md`, `artifacts/security/external_security_review.json` |

## Enterprise Procurement Checklist Mapping

| Procurement Ask | Response Artifact |
| --- | --- |
| Named independent review + date | `artifacts/security/external_security_review.json`, `artifacts/evidence/external_pentest_status.md` |
| Security test status | `END_TO_END_PROJECT_DOCUMENTATION.md` (current `pytest -q` status) |
| Residual risk statement | `artifacts/evidence/FALSE_NEGATIVE_TAXONOMY.md` |
| Supply-chain integrity | `artifacts/supply_chain/sbom.json`, `artifacts/evidence/supply_chain_validation.md` |
| Release approval evidence | `artifacts/evidence/security_signoff.md`, `artifacts/evidence/sre_slo_dr_signoff.md`, `artifacts/evidence/privacy_signoff.md` |
