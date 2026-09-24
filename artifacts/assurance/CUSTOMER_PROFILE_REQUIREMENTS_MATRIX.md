# Customer Profile Requirements Matrix

Date: 2026-03-18
Scope: Buyer-specific assurance requirements and required evidence references.

## Purpose

This matrix translates GuardianAI controls into customer-procurement language by segment, so sales/security responses are consistent and fast.

## Segment Matrix

| Customer Segment | Typical Requirement | What Buyer Asks For | GuardianAI Evidence |
| --- | --- | --- | --- |
| SMB SaaS | Baseline security posture, incident readiness | Security overview, architecture, auth controls, incident process | `SECURITY.md`, `../../docs/operations/END_TO_END_PROJECT_DOCUMENTATION.md`, `artifacts/evidence/security_signoff.md` |
| Mid-Market Enterprise | Security questionnaire + vendor risk intake | Control descriptions, test evidence, change management | `../../docs/operations/COMPLETE_PROJECT_DOCUMENTATION.md`, `../../docs/architecture/FEATURE_BENCHMARK_ANALYSIS.md`, `artifacts/evidence/compliance_bundle.json` |
| Large Enterprise Procurement | Independent testing + named assessor + dated report | Pen test summary, findings status, re-test status | `artifacts/security/external_security_review.json`, `artifacts/evidence/external_pentest_status.md` |
| Financial Services | SOC 2-aligned controls, auditable evidence, strict change governance | Control-to-framework mapping, traceable evidence, release signoff | `artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`, `artifacts/evidence/security_signoff.md`, `artifacts/evidence/sre_slo_dr_signoff.md` |
| Healthcare | HIPAA safeguard mapping, privacy handling, deletion/retention evidence | Administrative/technical safeguards, privacy workflow evidence | `artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`, `artifacts/evidence/privacy_signoff.md`, `artifacts/evidence/data_governance_audit.md` |
| EU Customers | GDPR + AI Act documentation posture | Automated decision controls, transparency, data handling controls | `artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`, `artifacts/evidence/privacy_signoff.md`, `artifacts/evidence/FALSE_NEGATIVE_TAXONOMY.md` |
| Security-Mature Buyers | Benchmark and residual-risk transparency | False-negative taxonomy, benchmark delta tracking | `../../docs/architecture/FEATURE_BENCHMARK_ANALYSIS.md`, `artifacts/evidence/FALSE_NEGATIVE_TAXONOMY.md`, `artifacts/performance/public_benchmark_report.json` |

## Response Packaging by Deal Stage

1. Stage 1 (Intro security review)
- Send:
  - `artifacts/assurance/NAMED_ASSURANCE_STATEMENT.md`
  - `SECURITY.md`
  - `../../docs/operations/EXECUTIVE_SUMMARY.md`

2. Stage 2 (Questionnaire / technical due diligence)
- Send:
  - `artifacts/assurance/SECURITY_QUESTIONNAIRE_QUICK_ANSWERS.md`
  - `artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`
  - `../../docs/operations/END_TO_END_PROJECT_DOCUMENTATION.md`

3. Stage 3 (Procurement + legal + risk committee)
- Send:
  - `artifacts/assurance/ENTERPRISE_PROCUREMENT_PACKET.md`
  - `artifacts/security/external_security_review.json`
  - `artifacts/evidence/security_signoff.md`
  - `artifacts/evidence/sre_slo_dr_signoff.md`
  - `artifacts/evidence/privacy_signoff.md`
