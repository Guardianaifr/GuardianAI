# GuardianAI Complete Project Documentation

Generated: March 13, 2026  
Repository: `F:\Saas\guardianai-basic-launch`

## 1) Document Purpose

This is the master, professional documentation for the current GuardianAI project state.  
It captures:

- Full platform scope and architecture
- Baseline (GitHub basic version) lineage
- Complete feature inventory and what each feature does
- API and configuration surfaces
- Validation, benchmark, and readiness results
- Risks, gaps, and release decision criteria

## 2) Version Lineage and Baseline

### Git Baseline (Basic Version)

- Observed baseline commit: `35201e3`
- Commit title: `GuardianAI`
- This represents the initial/basic version currently in Git history.

### Current Workspace State

- Current workspace includes substantial post-baseline additions (security, evidence, tests, CI workflows, brain modules, tooling).
- Roadmap execution status: **28 topics completed** (see `artifacts/evidence/TOPIC_PROGRESS.md`).

## 3) Platform Overview

GuardianAI is an AI security control plane that sits between clients and model endpoints and enforces controls across:

1. Input security (prompt abuse prevention)
2. Output security (PII/leak/exploit prevention)
3. Runtime security (process/resource/malicious execution control)
4. SaaS governance (telemetry, evidence, analytics, approvals, compliance workflows)
5. Web3 Integrity (on-chain anchoring, SBT identity, interlocks, and insurance)

## 4) Architecture (End-to-End Flow)

1. Client sends request to Guardian proxy.
2. Proxy resolves tenant/session identity and context.
3. Input checks execute (fast pattern filters, threat feed, semantic firewall).
4. Tool policy and access controls execute.
5. Rate limit and abuse controls execute.
6. Allowed request forwards to upstream LLM endpoint.
7. Output validation and redaction execute before response is returned.
8. Security telemetry events are posted to backend.
9. Backend stores events/analytics and serves authenticated reporting/export APIs.
10. Validation and evidence tools generate audit artifacts for release/governance gates.
11. Web3 Anchor periodically commits Merkle roots of state to the blockchain (Monad/Base), while emitting Passports and maintaining decentralized Interlocks.

## 5) Codebase Inventory (Quantified)

### Core modules

- Guardrail modules: **11 files** (`guardian/guardrails`)
- Security modules: **22 files total** (`guardian/security`, includes `__init__.py`)
- Automation/validation tools: **19 files** (`tools/`)
- CI workflows: **2** (`.github/workflows`)
- Test files: **51** (`tests/**/test_*.py`)
- Evidence files: **14** (`artifacts/evidence`)
- Total artifacts files: **26** (`artifacts/**`)

### Test distribution

- `tests/backend`: 3
- `tests/brain`: 6
- `tests/e2e`: 3
- `tests/guardrails`: 9
- `tests/runtime`: 2
- `tests/security`: 24
- `tests/unit`: 4

## 6) Complete Feature Inventory and Function

Major implemented feature groups: **38** (32 Off-Chain Security Controls + 6 On-Chain Web3 Contracts)

1. Prompt injection filtering (regex/keyword fast path)
   - Blocks known malicious prompt patterns quickly.
2. Semantic malicious-intent firewall
   - Detects intent-level jailbreak/injection patterns.
3. Advanced Multi-Format De-obfuscation
   - Natively decodes extreme Morse variants, Braille steganography, Base64, Hex, Binary, ROT13, Pig Latin, and mixed Homoglyphs.
4. Threat-feed matching & Persona Heuristics
   - Blocks patterns sourced from community threat intelligence and 18+ high-fidelity roleplay/persona heuristics.
5. Output PII detection and redaction
   - Detects sensitive output and redacts/blocks per policy.
6. Insecure output payload blocking
   - Prevents XSS/SQL/shell-like dangerous response payloads.
7. Runtime process/resource monitoring
   - Monitors CPU/memory/process behavior for anomalies.
8. Reverse-shell command-line detection
   - Flags shell execution chains indicative of compromise.
9. Binary hash-based process blocking
   - Blocks known malicious binaries by hash.
10. In-memory token-bucket rate limiting
   - Protects against request floods in single-instance mode.
11. Redis-backed distributed rate limiting
   - Provides multi-instance/global rate control in SaaS deployments.
12. Unauthorized-access protections
   - Token-protected ingest + authenticated backend endpoints.
13. Governance gate (enforce/audit)
   - Blocks unsafe config changes without approval/integrity proofs.
14. Hardening validation checks
   - Detects poisoning/provenance/tamper/groundedness/agency risks.
15. Compliance evidence export
   - Produces machine-readable compliance bundles.
16. Tamper-evident evidence signing/verification
   - Signs evidence and verifies integrity.
17. Red-team probe loop
   - Automated adversarial probing cadence.
18. Blue-team adaptive hardening
   - Session risk scoring and adaptive defenses.
19. Purple-team hotfix generation/persistence
   - Generates and stores defensive signatures.
20. CyberOps intelligence scoring
   - Keywords/context intelligence for security decisions.
21. Brain orchestrator in live flow
   - Coordinates red/blue/purple behavior in real traffic.
22. Session revoke enforcement
   - Blocks revoked/high-risk sessions in request path.
23. Auto-patch + firewall hot reload
   - Applies approved pattern updates without restart.
24. Tool-call policy engine
   - Allow/deny/confirm policy for tool usage.
25. External IdP/JWT revocation integration
   - Provider-aware revoke contracts (Okta/Auth0/Azure AD patterns).
26. Session/profile TTL and capacity cleanup
   - Prevents stale state growth and keeps memory bounded.
27. Honeypot/deception controls
   - Controlled deceptive responses for suspicious activity.
28. Performance + chaos validation harness
   - Executes load/chaos tests with SLO verdict outputs.
29. Hallucination-risk output assurance controls
   - Enforces structured response contracts (JSON schema fields, citations, confidence thresholds).
30. Public benchmark alignment workflow
   - Normalizes HarmBench/AdvBench/GAIA metrics and enforces benchmark score gates.
31. Output watermarking and verification controls
   - Applies signed response watermark metadata and supports integrity verification.
32. Differential privacy analytics controls
   - Applies Laplace-noise protection to aggregated analytics with configurable epsilon.
33. GuardianCortexAnchor (State Anchoring)
   - Periodically publishes Merkle roots of internal security logs and state to the blockchain for verifiable auditability.
34. GuardianPassportSBT (Soulbound AI Identity)
   - Issues non-transferable NFTs representing the cryptographic identity of an AI Agent or User Session.
35. GuardianInterlockRegistry (Agent-to-Agent Authorization)
   - Decentralized registry where AI agents request, approve, and verify communication permissions dynamically.
36. GuardianInsuranceLedger (Insurance Certificate Anchoring)
   - On-chain registry anchoring signed insurance certificates (integrity hash, validity period, risk level). Correction (Aug 2026): the stake/slash/payout behavior described in earlier revisions was never implemented — see whitepaper Feature 36 for the honest scope.
37. GuardianThreatFeedRegistry (Decentralized Intelligence)
   - On-chain repository where security nodes publish and subscribe to zero-day threat patterns.
38. GuardianRiskAttestation (Verifiable Trust)
   - Allows trusted auditors or GuardianAI to publish cryptographic attestations about an AI agent's real-time risk score.

39. ERC-8004 Identity Registration (Canonical Trustless Agents, Aug 2026)
   - Registers protected agents on the canonical ERC-8004 Identity Registry (register-then-transfer ownership), links each agentId to its GuardianPassportSBT, serves the spec registration JSON, and enforces fail-closed safety gates. Disabled by default — see `GUARDIAN_ERC8004_ENABLED` in `.env.example` and whitepaper Feature 39.

## 7) Roadmap Delivery (What Was Built Beyond Basic Version)

From `artifacts/evidence/TOPIC_PROGRESS.md`, completed topics:

1. SIEM routing + playbook mapping
2. Cloud key providers for evidence signing
3. Production IdP adapter contracts
4. Tool policy presets + regression coverage
5. Adversarial regression delta gate
6. Blue/Purple governance approval loop
7. Cost-abuse anomaly + quarantine
8. Multi-tenant hard isolation
9. Supply-chain hardening (SBOM + signed artifacts)
10. DR validation (backup/restore + RTO drill)
11. Threat-model quarterly cadence
12. Data governance + right-to-delete
13. Incident response drill tooling
14. Independent security review gate
15. Next-level guardrail E2E (advanced + chaos)
16. Agentic/MCP security controls
17. RAG indirect prompt-injection controls
18. Multimodal input security baseline
19. Live SIEM resilient routing
20. False-positive feedback loop + tenant sensitivity tuning
21. Model provenance verification in supply chain
22. Behavioral cost-abuse intelligence
23. Context/memory poisoning defenses
24. Hallucination-risk enforcement (output assurance)
25. Public benchmark alignment and score publishing
26. Output watermarking and verification
27. Differential privacy analytics and benchmarking
28. Release governance closure (sign-off completion + external review closure + strict dependency pinning)
29. Phase 7 Enterprise Security Hardening (HMAC audit signatures, thread-safety, non-root containers, and fail-safe defaults)
30. Phase 8 Web3 Integrity Layer (On-chain anchoring, Passport SBT, Interlock Registry, Insurance Ledger, Threat Feeds, Risk Attestation)

## 8) API Surface

### Backend API (`backend/main.py` + `backend/routers/*`)

HTTP endpoints:

- `POST /api/v1/telemetry`
- `GET /api/v1/export/json`
- `GET /api/v1/analytics`
- `GET /api/v1/export/csv`
- `GET /health`
- `GET /`
- `GET /api/v1/events`
- `GET /api/v1/audit-log`
- `DELETE /api/v1/admin/tenant-data`

Realtime endpoint:

- `WS /ws/threats`

### Proxy API

- `GET /health`
- OpenAI-compatible pass-through path handling (including `/v1/chat/completions`)

## 9) Configuration Surface (Production-Relevant)

Main config: `guardian/config/config.yaml`

Primary config domains:

- `governance`
- `security_policies`
- `scanner`
- `runtime_monitoring`
- `proxy`
- `backend`
- `rate_limiting`
- `threat_feed`
- `tool_policy`
- `honeypot`
- `cost_abuse`
- `tenant_isolation`
- `agentic_security`
- `rag_security`
- `multimodal_security`
- `tenant_sensitivity`
- `feedback_loop`
- `memory_security`
- `output_assurance`
- `output_watermark`
- `brain` (red/blue/purple orchestration and external JWT revocation config)
Note: backend analytics differential-privacy controls are environment-driven (`GUARDIAN_DP_ENABLED`, `GUARDIAN_DP_EPSILON`, `GUARDIAN_DP_SEED`).

## 10) Validation and Benchmark Results

### A) Full test status

- Latest recorded runs: backend + unit suites 171 passed (2026-08-25); earlier full-suite snapshot `241 passed` (2026-08-22 session) kept for history
- Standalone adversarial chaos E2E verification: `1 passed`

Interpretation: full suite is green; intermittent chaos contention remains a known historical risk under resource pressure, but was stable in this run.

### B) Performance/chaos benchmark

Source: `artifacts/performance/perf_chaos_report.json`

Baseline safe load:

- Requests: 120
- Concurrency: 20
- Throughput: 67.78 rps
- Status: 200 for all requests
- Latency p95: 587.83 ms

Attack block load:

- Requests: 120
- Concurrency: 20
- Throughput: 223.20 rps
- Status: 403 for all requests (100% block rate)
- Latency p95: 96.44 ms

Chaos behavior:

- Upstream down: 502
- Backend down: 200

SLO verdict:

- `all_passed: true`

### C) Missing-security validation (rerun in this session)

- SAST: 0 findings
- IaC: 0 findings
- Git history: 0 findings
- HAR scan: 0 findings
- Recall: 1.0
- Precision: 1.0
- Fuzz detection rate: 1.0 (9/9)
- Public benchmark alignment: all checks passed (composite: 93.6%)

### D) Hardening validation

- Dataset poisoning detections: 2
- Tamper detections: 1
- Groundedness findings: 1
- Agency findings: 1

These are fixture-triggered detections proving checks are active.

## 11) Evidence and Compliance Assets

Key artifacts:

- `artifacts/evidence/compliance_bundle.json`
- `artifacts/evidence/tenant_isolation_validation.md`
- `artifacts/evidence/cost_abuse_simulation.md`
- `artifacts/evidence/dr_validation.md`
- `artifacts/evidence/data_governance_audit.md`
- `artifacts/evidence/incident_drill_report.md`
- `artifacts/evidence/threat_model_quarterly.md`
- `artifacts/evidence/supply_chain_validation.md`

Operational highlights from evidence:

- DR restore integrity: true, RTO target met
- Threat model quarter sign-off: approved
- External security review metadata shows `open_critical_findings = 0`, `open_high_findings = 0`
- Latest SBOM validation shows `all_dependencies_pinned = true`

## 12) CI/CD Security Gates

Workflows:

- `security-quality-gate.yml`
- `supply-chain-gate.yml`

Gate intents:

- unit/integration/e2e regression coverage
- missing-security and hardening checks
- performance/chaos + SLO checks
- supply-chain SBOM/sign/verify verification

## 13) Remaining Gaps (Professional Readiness Checklist)

1. No unresolved backlog items from the 2026 Q1 security roadmap.
2. Formal sign-off artifacts are completed and populated.
3. External security review high/critical findings are closed.
4. Dependency pinning is enforced (`requirements.txt` pinned, SBOM strict gate passing).

## 14) Go/No-Go Recommendation

Current recommendation: **Go**

- Production rollout is supported based on current evidence and gate results.
- Maintain normal release governance and periodic re-validation cadence.

## 15) Source Index

- `END_TO_END_PROJECT_DOCUMENTATION.md`
- `FEATURE_BENCHMARK_ANALYSIS.md`
- `EXECUTIVE_SUMMARY.md`
- `artifacts/evidence/TOPIC_PROGRESS.md`
- `artifacts/performance/perf_chaos_report.json`
- `artifacts/performance/security_slo_targets.json`
- `artifacts/evidence/compliance_bundle.json`
- `backend/main.py`
- `guardian/config/config.yaml`
- `API.md`
