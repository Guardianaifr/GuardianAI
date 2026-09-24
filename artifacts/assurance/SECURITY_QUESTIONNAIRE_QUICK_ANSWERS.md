# Security Questionnaire Quick Answers

Date: 2026-03-18
Use: Rapid response template for customer security questionnaires.

## Product and Security Model

1. What does GuardianAI do?
- GuardianAI is a control-plane security layer for LLM applications, enforcing prompt/input defenses, output safeguards, runtime controls, and telemetry/governance.

2. Is multi-tenant isolation supported?
- Yes. Tenant scoping is enforced in request/session handling and backend event storage/query paths.

3. How are malicious prompts handled?
- Multi-layer controls include keyword/regex filters, semantic firewall checks, threat feed checks, and policy-based blocking.

## Data and Privacy

4. Do you support tenant data deletion?
- Yes. Tenant-scoped delete workflow is implemented (`DELETE /api/v1/admin/tenant-data`).

5. Do you provide privacy-oriented analytics controls?
- Yes. Differential privacy mode for aggregated analytics is available with configurable epsilon.

## Output Safety and Integrity

6. How do you prevent sensitive output leaks?
- Output validation and redaction controls detect and block/redact PII and unsafe content.

7. Do you support verifiable output integrity?
- Yes. Output watermarking applies signed metadata and supports verification tooling.

## Security Validation

8. Are automated tests and benchmarks available?
- Yes. Full validation includes unit/runtime/backend/e2e tests, performance/chaos reports, and public benchmark alignment artifacts.

9. What is current test status?
- Current full suite status: `pytest -q` -> 244 passed.

## Third-Party Review and Findings

10. Is there independent review evidence?
- Yes. External review metadata includes reviewer, date, and current findings status (`open_critical_findings: 0`, `open_high_findings: 0`).

## Supply Chain and Release Integrity

11. Is dependency pinning enforced?
- Yes. Current SBOM indicates pinned dependencies (`all_dependencies_pinned: true`).

12. Is release integrity verifiable?
- Yes. Release manifest signing and verification tooling is provided.

## Key References

- `artifacts/assurance/ENTERPRISE_PROCUREMENT_PACKET.md`
- `artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`
- `artifacts/security/external_security_review.json`
- `artifacts/supply_chain/sbom.json`
- `../../docs/operations/END_TO_END_PROJECT_DOCUMENTATION.md`
