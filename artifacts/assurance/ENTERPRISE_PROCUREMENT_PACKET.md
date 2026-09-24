# Enterprise Procurement Packet

Date: 2026-03-18
Audience: Enterprise security, procurement, legal, and risk teams.

## Packet Overview

This packet provides the minimum evidence bundle for enterprise due diligence.

## 1) Security Program Summary

- Product security policy: `SECURITY.md`
- End-to-end architecture and controls: `../../docs/operations/END_TO_END_PROJECT_DOCUMENTATION.md`
- Executive release posture: `../../docs/operations/EXECUTIVE_SUMMARY.md`

## 2) Control Validation and Testing

- Full test status and benchmark posture: `../../docs/architecture/FEATURE_BENCHMARK_ANALYSIS.md`
- Detailed implementation and readiness documentation: `../../docs/operations/COMPLETE_PROJECT_DOCUMENTATION.md`
- Regression and E2E validation evidence:
  - `tests/e2e/test_guardrail_advanced_e2e.py`
  - `tests/e2e/test_guardrail_adversarial_chaos_e2e.py`

## 3) Independent Review and Findings

- External review metadata: `artifacts/security/external_security_review.json`
- External pentest status statement: `artifacts/evidence/external_pentest_status.md`

## 4) Governance and Sign-Off Evidence

- Security signoff: `artifacts/evidence/security_signoff.md`
- SRE/SLO/DR signoff: `artifacts/evidence/sre_slo_dr_signoff.md`
- Privacy signoff: `artifacts/evidence/privacy_signoff.md`
- Rollback validation signoff: `artifacts/evidence/rollback_validation.md`

## 5) Supply-Chain and Release Integrity

- SBOM artifact: `artifacts/supply_chain/sbom.json`
- Supply-chain validation report: `artifacts/evidence/supply_chain_validation.md`
- Release signature tooling:
  - `tools/sign_release_artifacts.py`
  - `tools/verify_release_artifacts.py`

## 6) Framework and Compliance Mapping

- SOC2/HIPAA/GDPR/AI Act mapping: `artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`
- Customer segment requirement mapping: `artifacts/assurance/CUSTOMER_PROFILE_REQUIREMENTS_MATRIX.md`

## 7) Residual Risk Transparency

- False-negative taxonomy and benchmark residuals:
  - `artifacts/evidence/FALSE_NEGATIVE_TAXONOMY.md`
  - `artifacts/performance/public_benchmark_report.json`

## 8) Standard Procurement Answers (Quick Pull)

- Security questionnaire quick answers:
  - `artifacts/assurance/SECURITY_QUESTIONNAIRE_QUICK_ANSWERS.md`
