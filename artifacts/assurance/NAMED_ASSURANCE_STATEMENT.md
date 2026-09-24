# Named Assurance Statement

Date: 2026-03-18
Project: GuardianAI (`guardianai-basic-launch`)

## Statement

GuardianAI maintains a defense-in-depth security control layer for LLM traffic with validated controls across input protection, output assurance, runtime controls, supply-chain validation, and compliance evidence workflows.

Current assurance posture includes:

- Full test suite passing (`pytest -q`: 244 passed)
- Public benchmark alignment: HarmBench 72.8% strict, AdvBench 99.0% strict, security-gate Tier 1+2 97.6% strict (source: definitive_benchmark_v4.json, 2026-08-08). Prior composite score (93.6%) retracted — see ../../docs/whitepaper/WHITEPAPER_PUBLIC.md Section 6.2.
- External review metadata with no open critical or high findings
- Dependency pinning enforced in current SBOM (`all_dependencies_pinned: true`)

## Independent Review Metadata

- Reviewer: Independent Security Partner
- Review date: 2026-03-18
- Scope: Release readiness and architecture delta review
- Open critical findings: 0
- Open high findings: 0
- Re-test status: passed

Reference: `artifacts/security/external_security_review.json`

## Evidence References

- Security signoff: `artifacts/evidence/security_signoff.md`
- SRE/DR signoff: `artifacts/evidence/sre_slo_dr_signoff.md`
- Privacy signoff: `artifacts/evidence/privacy_signoff.md`
- Supply-chain validation: `artifacts/evidence/supply_chain_validation.md`
- Benchmark and residual risk: `../../docs/architecture/FEATURE_BENCHMARK_ANALYSIS.md`, `artifacts/evidence/FALSE_NEGATIVE_TAXONOMY.md`
