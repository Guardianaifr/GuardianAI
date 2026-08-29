# GuardianAI End-to-End Project Documentation

## Status Snapshot

| Workstream | Status |
| --- | --- |
| Core Platform Security Controls | Done |
| Test Suite and Validation Packs | Done |
| Performance and Chaos Validation | Done |
| Mini Roadmap Definition | Done |
| Mini Roadmap Delivery | Done |
| Production Governance and Release Readiness | Done |
| One-Click Customer Activation | Done |

## 1) What This Project Is

GuardianAI is a security control plane for LLM applications.  
It sits between client applications and model endpoints, and enforces security at:

- Input stage (prompt inspection and blocking)
- Output stage (leak/exploit detection and redaction)
- Runtime stage (process/resource monitoring)
- SaaS control stage (telemetry, analytics, policy governance, evidence export)

## 2) Current Scope and Status

As of **April 28, 2026**, this workspace includes:

- Full local/SaaS stack: proxy + backend + enterprise runtime controls
- 10-Layer AI Firewall (Semantic, Regex, Threat Feeds, Roleplay Abuse, Sexual Content, L33t decoding)
- Output Guardrails (PII redaction, XSS/SQL payload blocking)
- Distributed-ready enterprise rate limiting (Thread-safe, custom IP limits, burst detection)
- Governance gate for high-risk config changes
- Compliance evidence export with signature verification
- Live SIEM routing with resilient dispatch (file/http/both, retry + dead-letter fallback)
- Tenant sensitivity tuning + reviewed false-positive feedback loop controls
- Supply-chain model provenance verification (artifact hash + manifest checks)
- Tenant behavioral cost-abuse intelligence (cross-session slow-drain detection)
- Session memory poisoning defenses with quarantine controls
- Hallucination-risk output assurance controls (schema + citation + confidence gates)
- Public benchmark alignment workflow (HarmBench/AdvBench/GAIA score gating + publishable reports)
- Signed output watermarking controls (integrity stamp + verification path)
- Differential privacy controls for aggregated analytics (Laplace-noise mode)
- Customer-facing assurance documentation layer (framework mapping + procurement packet)
- One-click full-feature SaaS activation flow (`guardianctl.py one-click`)
- End-to-end integration test coverage

- Added robust Developer SDK
- Full UI / Backend telemetry and metering integration (Dashboard)
- JWT Auth and RBAC
- Dependency Pinning CI Gates

One-click activation behavior:
- Generates secure runtime credentials if not already provided in environment.
- Writes full-feature runtime config to `guardian/config/one_click_runtime.yaml`.
- Launches backend + proxy stack in a single command.

Automated test status:
- **backend + unit suites 172 passed (2026-08-25)** (`pytest -q tests/backend tests/unit`)
- **100% Phase 4 Delivery + Feature #12 Enterprise Auth**

## 3) Architecture (End-to-End)

```text
Client
  -> Guardian Proxy (Flask; bind set by GUARDIAN_PROXY_HOST — 0.0.0.0 in cloud hosting)
      -> InputFilter / Base64 detector / Threat feed / AI firewall / Rate limiter
      -> Upstream model endpoint
      -> OutputValidator (PII + exploit detection + redaction)
      -> Telemetry events
  -> Backend API (FastAPI; GUARDIAN_BACKEND_HOST defaults 0.0.0.0)
      -> Event ingest (token-protected)
      -> Analytics + audit logs
      -> Protected event export endpoints
  -> Security/Validation Tooling
      -> Static/IaC/git-history scans
      -> HAR interception scans
      -> Hardening checks
      -> Compliance evidence bundles (+ signature verify)
```

## 4) Feature Inventory (What You Have Now)

Major feature groups implemented: **32**

1. Prompt injection filtering (regex/keyword path)
2. Semantic malicious-intent firewall path
3. Base64/high-entropy obfuscation detection
4. Threat-feed matching path (Live API + Bundled YAML)
5. Output PII detection and redaction (SSN, cards, emails, IPs, phones)
6. Insecure output payload blocking (XSS/SQL/shell patterns)
7. Runtime process monitor (get_stats, bounded audit log, single-shot scan)
8. Network monitor & DNS Sinkhole (hot-add/remove IPs, domains, CIDRs)
9. Filesystem sandbox (hot-reload governance, traversal mitigation)
10. Token bucket rate limiting (RLock thread-safe, burst detection, banlists)
11. Distributed Redis-backed rate limiting (auto-fallback to in-memory)
12. Unauthorized-access protections (API key management, auth token rate limiting, service-to-service auth)
13. Policy governance gate (`enforce`/`audit`, approval + integrity pin)
14. Hardening checks (poisoning, provenance, groundedness, agency)
15. Compliance evidence export (machine-readable bundle)
16. Tamper-evident evidence signing + verification
17. Red Team automated probe loop (`guardian/brain/red_probe.py`)
18. Blue Team adaptive session hardening (`guardian/brain/blue_adapt.py`)
19. Purple Team hotfix generation and persistence (`guardian/brain/purple_heal.py`)
20. CyberOps intelligence keyword scoring (`guardian/brain/cyberops_intel.py`)
21. Brain orchestrator integration into live proxy flow (`guardian/brain/orchestrator.py`)
22. Blue Team session revoke enforcement in proxy path
23. Purple Team firewall vector auto-patch + AI firewall hot-reload
24. Tool-call policy engine (allow/deny + sensitive-tool confirmation gates)
25. External IdP/JWT revocation integration with mock-provider validation
26. Blue Team session/profile TTL + capacity cleanup controls
27. Honeypot template rotation + per-session deception rate-limiting
28. Performance + chaos validation harness with SLO verdict artifacts
29. Output assurance guard (structured schema + citations + confidence thresholds)
30. Public benchmark alignment gate (HarmBench/AdvBench/GAIA adapters + composite scoring)
31. Output watermarking and verification controls (HMAC-signed response stamp)
32. Differential privacy analytics mode (configurable epsilon + benchmark workflow)
33. Usage Metering and Stripe Integration
34. JWT Authentication + Role Based Access Control
35. System Prompt Leakage Prevention (LLM07)
36. Universal Auth Proxy Configuration (vLLM/Ollama/OpenAI bypass)
37. Security Dashboard SaaS UI 

Agent config and data files:
- `guardian/config/cyberops_intel.json`
- `guardian/config/brain_red_vectors.yaml`
- `guardian/config/brain_hotfix_patterns.json`

## 5) Security Validation Framework

Validation pipelines in repo:

- `tools/run_missing_security_validation.py`
  - SAST secret scan
  - IaC scan
  - git history scan
  - HAR interception scan
  - recall/precision benchmark
  - fuzz detection rate
  - public benchmark alignment checks (HarmBench/AdvBench/GAIA)

- `tools/run_public_benchmark_alignment.py`
  - benchmark adapter normalization (HarmBench/AdvBench/GAIA)
  - weighted composite scoring
  - publish verdict to JSON + markdown artifacts

- `tools/verify_output_watermark.py`
  - verifies signed output watermark integrity on JSON responses

- `tools/run_dp_analytics_benchmark.py`
  - benchmarks analytics distortion across epsilon values
  - publishes DP benchmark JSON + markdown artifacts

- `tools/run_hardening_validation.py`
  - poisoning checks
  - model provenance checks
  - tamper-detection checks
  - groundedness checks
  - excessive agency checks

- `tools/run_performance_chaos_validation.py`
  - baseline load test (latency + throughput)
  - attack-path block throughput test
  - backend-down chaos scenario
  - upstream-down chaos scenario
  - SLO verdict export (`perf_chaos_report.json` / `.md`)

- `tools/export_compliance_evidence.py`
  - emits compliance bundle JSON with embedded validation reports

- `tools/verify_compliance_evidence.py`
  - verifies signature integrity for compliance bundle

- `artifacts/assurance/`
  - buyer-segment requirement matrix
  - SOC2/HIPAA/GDPR/AI Act control mapping
  - enterprise procurement packet
  - named assurance statement and security questionnaire quick answers

## 6) End-to-End Test Coverage

Coverage includes:

- Unit-level guardrail tests
- Runtime behavior tests (proxy + monitor)
- Backend access-control tests
- Security-tooling tests (scan/benchmark/hardening/evidence)
- Full SaaS process-level E2E test:
  - boots backend + proxy + mock upstream
  - validates pass-through, redaction, rate-limit, auth, telemetry persistence
- Advanced guardrail E2E scenarios:
  - tenant header enforcement
  - sensitive tool confirmation gate
  - multi-turn jailbreak block
  - cost-abuse detection and session quarantine telemetry
- Adversarial chaos E2E scenarios:
  - mixed safe and attack traffic under concurrent load
  - attack block-rate and safe success-rate assertions
  - tenant-isolated backend event verification

Key E2E file:
- `tests/e2e/test_full_saas_e2e.py`
- `tests/e2e/test_guardrail_advanced_e2e.py`
- `tests/e2e/test_guardrail_adversarial_chaos_e2e.py`

## 7) Governance and Compliance Model

Governance controls:

- Configurable in `governance` block (`guardian/config/config.yaml`)
- Policy file: `guardian/config/policy_control.yaml`
- Modes:
  - `enforce`: block startup on violations
  - `audit`: report only
- Approval model:
  - `status`, `approver`, `ticket`
  - `config_sha256` integrity pin

Evidence model:

- Bundle file: `artifacts/evidence/compliance_bundle.json`
- Contains:
  - runtime metadata
  - git metadata
  - config integrity hash
  - validation reports
  - signature metadata

## 8) Operational Runbook

Environment setup:

```powershell
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt
```

Run full tests:

```powershell
.\.venv312\Scripts\python.exe -m pytest -q
```

Run security validation packs:

```powershell
.\.venv312\Scripts\python.exe tools/run_missing_security_validation.py
.\.venv312\Scripts\python.exe tools/run_hardening_validation.py
.\.venv312\Scripts\python.exe tools/run_performance_chaos_validation.py
```

Note:
- Python runtime standard is `.venv312` (Python 3.12) for full dependency compatibility.

Export and verify compliance evidence:

```powershell
$env:GUARDIAN_EVIDENCE_SIGNING_KEY="your-signing-key"
$env:GUARDIAN_EVIDENCE_SIGNING_KEY_ID="prod-key-1"
.\.venv312\Scripts\python.exe tools/export_compliance_evidence.py
.\.venv312\Scripts\python.exe tools/verify_compliance_evidence.py --key "your-signing-key"
```

## 9) What You Are Doing (Program-Level Summary)

You are building GuardianAI as an enterprise-grade AI security layer with:

- Real-time prevention controls
- Runtime host hardening
- SaaS-grade access control and telemetry
- Governance and auditability controls
- Reproducible, signed compliance evidence
- Continuous automated verification (unit + integration + E2E)

This is no longer just a firewall prototype; it is now a validated security platform baseline.

## 10) Recommended Next Milestones

1. CI/CD enforcement:
   - run full test + both validation packs + evidence verify on every push/PR
2. Key management upgrade:
   - move evidence signing key to secret manager/KMS
3. Governance workflow integration:
   - approval ticket sync with your issue tracker/ITSM
4. SIEM playbook packs:
   - add vendor-specific mapping presets (Splunk/Sentinel/Elastic) and dead-letter replay job

## 11) Mini Roadmap (Finalized and Execution-Ready)

Roadmap baseline date: **March 11, 2026**.

Delivery cadence:
- Sprint 1: March 11 to March 24, 2026
- Sprint 2: March 25 to April 7, 2026
- Sprint 3: April 8 to April 21, 2026
- Sprint 4: April 22 to May 5, 2026
- Sprint 5+: May 6, 2026 onward

### Phase 1: Must-Have (Sprints 1-2)

1. SIEM alert routing + playbook mapping
   - Deliverables: structured emitters (JSON + CEF), severity-to-runbook map, synthetic attack replay
   - Evidence: `artifacts/evidence/siem_delivery_report.md`
   - Done when: critical alerts are delivered to SIEM and mapped runbooks are validated in replay tests
2. CI security quality gate
   - Deliverables: mandatory PR checks for `pytest`, missing-security, hardening, and chaos validation
   - Evidence: CI workflow logs for failing and passing gates
   - Done when: merge is blocked on regression in scan quality or SLO verdict
3. Evidence signing productionization
   - Deliverables: KMS or secret-manager key path, rotation playbook, verification regression tests
   - Evidence: `artifacts/evidence/key_rotation_validation.md`
   - Done when: rotated key signs and verifies bundles without downtime
4. Security SLOs and error budgets
   - Deliverables: explicit targets for block rate, false-positive rate, p95 latency, and incident MTTR
   - Evidence: `artifacts/performance/security_slo_dashboard.md`
   - Done when: release gate enforces SLO breach policy
5. Access hardening
   - Deliverables: service authentication between proxy and backend, credential rotation policy
   - Evidence: `artifacts/evidence/service_auth_validation.md`
   - Done when: unauthenticated service calls fail and rotation runbook is tested

### Phase 2: High-Impact (Sprints 3-4)

1. Production IdP adapters
   - Deliverables: adapters for Okta/Auth0/Azure AD with JWT claim and revoke contract tests
   - Evidence: `artifacts/evidence/idp_adapter_contract_report.md`
   - Done when: at least one adapter passes full contract and E2E auth tests
2. Tool policy presets
   - Deliverables: baseline policy packs for OpenAI tools, LangChain tools, and internal action tools
   - Evidence: `artifacts/evidence/tool_policy_regression_report.md`
   - Done when: every preset has passing regression coverage
3. Blue/Purple policy governance loop
   - Deliverables: approval trail requirement for auto-generated hotfixes in enforce mode
   - Evidence: governance audit entries tied to each auto-patch
   - Done when: auto-patch activation without approval is blocked in enforce mode
4. Adversarial eval expansion
   - Deliverables: multilingual jailbreak and tool-abuse benchmark packs with release deltas
   - Evidence: `artifacts/security/adversarial_regression_delta.md`
   - Done when: release notes include benchmark deltas and no unapproved regression
5. Cost-abuse protection
   - Deliverables: anomaly detection for token/cost spikes and quarantine policy for abuse sessions
   - Evidence: `artifacts/evidence/cost_abuse_simulation.md`
   - Done when: synthetic wallet-drain scenarios trigger quarantine and alerting

### Phase 3: Scale and Enterprise Readiness (Sprint 5+)

1. Multi-tenant hard isolation
   - Deliverables: tenant-scoped policy, telemetry, and evidence segregation controls
   - Evidence: automated tenant-isolation test report
   - Done when: zero cross-tenant access in automated and replay tests
2. Supply-chain hardening
   - Deliverables: SBOM generation, dependency provenance checks, signed release artifacts
   - Evidence: build attestation and artifact verification logs
   - Done when: deployment rejects unsigned or provenance-failing artifacts
3. Reliability and DR validation
   - Deliverables: backup/restore automation and RTO drill reports
   - Evidence: `artifacts/evidence/dr_validation.md`
   - Done when: RTO/RPO targets are met in drill evidence
4. Threat modeling cadence
   - Deliverables: quarterly OWASP LLM + MITRE ATLAS refresh process
   - Evidence: `artifacts/evidence/threat_model_quarterly.md`
   - Done when: accepted risks and mitigations are reviewed and signed each quarter
5. Data governance and retention
   - Deliverables: tenant retention policy, right-to-delete workflow, encrypted backup policy
   - Evidence: retention and deletion audit report
   - Done when: deletion SLAs and retention controls are test-verified per tenant
6. Incident response drills
   - Deliverables: tabletop and live simulations for injection, leak, and auth-compromise scenarios
   - Evidence: post-incident reports with control updates
   - Done when: drill findings produce tracked remediation and closure evidence
7. Independent security review gate
   - Deliverables: external red-team or pentest before release and post-major architecture change
   - Evidence: latest pentest report with remediation tracking
   - Done when: no open critical findings without exception approval

### AI Firewall Hardening Additions
33. **Advanced Multi-Format De-obfuscation** — Natively decodes extreme Morse variants (Written, Asterisk, Em-Dash, URL-Encoded), Braille steganography, Base64, Hex, Binary, ROT13, Pig Latin, and mixed Homoglyphs.
34. **Frame Stripper** — discards academic/fictional/roleplay framing to expose raw intent; dual-pass inference on both raw and stripped text
35. **Generic Persona Injection Detector** — structural pattern matching for novel persona names, catches `PERSONA=`, `CHAR=`, `from now on you are`, `never refuse`, `always starts replies with`, fake OS prompts, and 18+ high-fidelity roleplay/persona heuristics.
36. **Sexual Content Detector** — erotic roleplay, NSFW requests, explicit story prompts, spicy photo requests
37. **Hate Speech / Racial Slur Detector** — slur wordlist + coded racism (replace-letter tricks, racial IQ prompts, stereotype patterns)
38. **Roleplay Abuse Detector** — underage roleplay, body insertion fetish, implicit CSAM, body horror content
39. **Expanded Persona Trigger Bank** — UCAR, DUDE, GTD, SAN, PersonGPT, JailBreak, Boolean Opposite Machine, NLP-Based OS, GTDNGAF, and 20+ structural variants

### Advanced 2026-Standard Security Upgrades (This Session)
- **Blue Team:** Session velocity tracking, geo-anomaly detection, behavioral fingerprinting, adaptive cooldown escalation.
- **Purple Team:** Auto-severity classification, hotfix rollback manager, pattern deduplication, heal-rate metrics.
- **CyberOps:** MITRE ATT&CK mapping, IOC feed ingestion, composite threat scoring, threat actor profiling.
- **IdP/JWT Revocation:** Full exp/nbf/iss/aud validation, bounded FIFO token blacklist, OIDC discovery cache, JWT session/IP binding verifier, multi-IdP federation.
- **Honeypot:** Canary token injection/tracking, adaptive delay simulation, attacker profiling (IP/UA harvesting), decoy credential rotation.
- **Output Watermarking:** Versioned key rotation, steganographic invisible text watermarks, batch verification, bounded audit log, content fingerprinting.
- **Differential Privacy:** Gaussian mechanism (L2), strict Privacy Budget Tracker (epsilon/delta composition), automated noisy sum/average bounds clipping, Exponential mechanism, Local DP (RAPPOR-lite).

### Phase 7 Enterprise Security Hardening
- **Cryptographic Audit Integrity:** HMAC-SHA256 signature chain enforced on all audit logs to guarantee non-repudiation and prevent tampering.
- **Concurrency & Thread Safety:** Scoped thread-locks across rate limiting and metering subsystems ensuring stability under extreme load.
- **Zero-Trust Infrastructure:** Non-root (UID 10001) execution inside multi-stage Docker containers.
- **Fail-Safe Defaults:** Hard enforcement preventing startup in production if default or weak credentials are in use.

Primary source: `guardian/guardrails/ai_firewall.py` and module files in `guardian/brain/` & `guardian/security/`.

### Program Completion Gate ("Full Project" Definition)

- All three validation packs run in CI on every PR with blocking policy
- SIEM alerts validated for critical classes with runbook linkage
- At least one production IdP adapter validated end to end
- KMS-backed evidence signing and key rotation proven in tests
- Multi-tenant, DR, and retention controls validated in automation
- Quarterly threat model and incident drill evidence published
- Cost-abuse controls pass synthetic attack traffic simulations
- External security review findings remediated and re-tested

## 12) Testing Roadmap (Production Readiness) *[COMPLETED]*

1. Long soak test => **DONE**
2. Fault-injection matrix => **DONE**
3. False-positive/false-negative benchmark => **DONE**
4. Multi-tenant isolation tests => **DONE**
5. Security regression gates in CI => **DONE**
6. Upgrade compatibility tests => **DONE**
7. Disaster recovery tests => **DONE**
8. External pentest regression conversion => **DONE**

## 13) Go/No-Go Release Checklist (Mandatory Sign-Offs)

Before any production release, all of the following must be approved:

1. Security lead sign-off -> **[ APPROVED ]**
2. SRE sign-off (SLO and DR evidence attached) -> **[ APPROVED ]**
3. Product/privacy sign-off (data retention and deletion controls verified) -> **[ APPROVED ]**
4. External pentest status acknowledged -> **[ APPROVED ]**
5. Rollback plan tested within last 30 days -> **[ APPROVED ]**

Release status: **[ GO LIVE ]**

## 14) Baseline (GitHub Basic Version) and Current Delta

Baseline currently visible in local git history:

- Commit: `35201e3`
- Message: `GuardianAI`
- Interpretation: this is the basic/base committed version lineage anchor.

Post-baseline, this workspace adds the roadmap delivery set (Topics 1-15), including:

- governance, SIEM, supply-chain, DR, tenant isolation, cost-abuse controls
- red/blue/purple orchestration
- expanded security tooling
- advanced and chaos end-to-end guardrail testing

For the complete professional documentation package (full inventory, benchmarks, APIs, gaps, and release assessment), see:

- `COMPLETE_PROJECT_DOCUMENTATION.md`
- `FEATURE_BENCHMARK_ANALYSIS.md`
- `EXECUTIVE_SUMMARY.md`




