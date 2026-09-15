# GuardianAI Roadmap

**Updated**: September 12, 2026  
**Vision**: Expand from an LLM firewall into the industry's most complete AI security control plane.  
**Current**: 44 features shipped · Monad Metropolis Track 04 & Sponsor Bounties Delivered (Envio HyperIndex, Category Labs Mera Passkey Enclave, Agent Middleware SDK, 166 Hard Audit Suite) · Production Go  

---

## Completed Milestones (v1.0 - v1.2)

- ✅ 33 major security feature groups
- ✅ 29 roadmap topics delivered
- ✅ Full OWASP LLM Top 10 (2025) coverage — **10/10**
- ✅ Benchmark alignment on real datasets (3,211 prompts, 8 datasets): AdvBench 99.0% strict, HarmBench 72.8% strict — see WHITEPAPER_PUBLIC.md §6 and `artifacts/evidence/definitive_benchmark_v4.json`
- ✅ **ERC-8004 Identity Registration (Aug 2026):** canonical Trustless Agents registry integration, register-then-transfer ownership handoff, fail-closed safety gates, 42-test offline suite (WHITEPAPER_PUBLIC.md Feature 39)
- ✅ **Identity Gate & Point-of-Interaction Enforcement (Sep 2026):** pre-flight RPC relay & agentic control plane enforcement, on-chain `ownerOf` validation, database-level hot-wallet collision defense, and shadow observation mode (WHITEPAPER_PUBLIC.md Feature 40)
- ✅ **GuardianPolicyGuard & Monad Parallel EVM Guardrails (Sep 2026):** 10 Solidity invariants, EIP-712 cryptographic verification, zero-trust function selector allowlists (RBAC), rolling 24h outflow caps, and conflict-free namespaced nonces scaling to 10,000 TPS on Monad Testnet (Feature 41)
- ✅ **Agent Middleware SDK (@guardianai/middleware) (Sep 2026):** Drop-in ElizaOS memory-poisoning prevention plugin and Viem security decorator (49 TS unit tests passing) (Feature 42)
- ✅ **Envio HyperIndex Real-Time Indexer (Sep 2026):** Multi-contract blockchain event streaming across 5 Monad contracts with sub-second GraphQL feeds and 36 passing tests (Feature 43)
- ✅ **Category Labs Mera Passkey PRF Enclave (Sep 2026):** Sovereign, non-wallet agent identity minting (Ed25519) and zero-knowledge memory encryption (AES-256-GCM + HKDF) with active tamper tripwires (`MEMORY_POISONING_DETECTED`) (Feature 44)
- ✅ **Empirical Hard Audits on Real-World Datasets (Sep 2026):** 166/166 hard test assertions passing (`npm run test:hard`); 1,061 live attack vectors tested across Lakera Gandalf, BIPIA, SecLists, and BLNS corpora (96.23% catch rate, 100% tamper precision, sub-0.5ms P50 latency)
- ✅ SLO verdict: all_passed = true

---

## Phase 4 — Go-to-Market (Weeks 1–6)

Goal: Production-ready, revenue-generating, EU-compliant.

### Sprint 0 — Urgent Compliance (Week 1) ✅ COMPLETE
1. ~~**EU AI Act Compliance Module**~~ ✅ **COMPLETE** (April 20, 2026)
   - Risk classification (Annex III), RMS generator (Art. 9), Transparency report (Art. 13)
   - Conformity checklist (12 items), ISO 42001 QMS mapping (7 clauses)
   - 38 tests passing · CLI tool generates JSON + Markdown reports
   - Assessment result: **98% compliant, 8/8 articles passed**

2. ~~**System Prompt Leakage Protection**~~ ✅ **COMPLETE** (April 20, 2026)
   - 3-layer detection: pattern matching, n-gram overlap, extraction attempt boosting
   - 23 tests passing · OWASP LLM07 covered · Integrated into output pipeline

### Sprint 1 — Auth & Revenue (Weeks 2–3)
3. ~~**JWT Authentication + RBAC**~~ ✅ **COMPLETE** (April 20, 2026)
   - HS256 JWT with access/refresh tokens, 4 roles, 13 permissions
   - 6 API endpoints: login, refresh, logout, register, me, users
   - 37 tests passing · Tenant scoping · Token revocation · Auto-bootstrap

4. ~~**Sign-Off Document Completion**~~ ✅ **COMPLETE** (April 20, 2026)
   - Updated all 5 sign-off documents with Phase 4 evidence, adversarial test results, benchmarks

5. ~~**Usage Metering + Billing + Pricing Tiers**~~ ✅ **COMPLETE** (April 20, 2026)
   - 4 tiers: Free ($0) / Starter ($49/mo) / Pro ($299/mo) / Enterprise (custom)
   - Per-tenant daily request + token metering with SQLite persistence
   - Tier-based rate limiting, usage history, admin dashboard data
   - 29 tests passing · Thread-safe · Concurrent metering verified

### Sprint 2 — Visibility & Developer Experience (Weeks 4–5)
6. ~~**Security Dashboard & Analyst UI**~~ ✅ **COMPLETE** (April 20, 2026)
   - JWT login flow, real-time WebSocket event feed, threat breakdown chart
   - Dark glassmorphism UI, stats cards, responsive layout
   - Route: `/site/dashboard` · Integrated with all backend APIs

7. ~~**Developer SDK (Python + JavaScript)**~~ ✅ **COMPLETE** (April 20, 2026)
   - `from guardianai import GuardianAI` — one-liner integration
   - JWT auth, prompt scanning, response validation, OpenAI proxy, auto-retry
   - 23 tests passing · Thread-safe · Mock server test harness

### Sprint 3 — Infrastructure (Week 6)
8. ~~**Universal Auth Proxy Mode**~~ ✅ **COMPLETE** (April 20, 2026)
   - Supports Ollama, LocalAI, vLLM, llama.cpp, OpenAI
   - Request translation, model allowlisting, header stripping, token bucket rate limiter
   - 28 tests passing

9. ~~**Dependency Pinning CI Gate**~~ ✅ **COMPLETE** (April 20, 2026)
   - Scans requirements files, detects unpinned deps, CycloneDX SBOM generation
   - CLI tool: `python tools/check_dep_pinning.py`
   - 23 tests passing

---

## Phase 5 — Advanced Threats (Weeks 7–14)

Goal: Full OWASP Agentic Top 10 coverage, ahead of all competitors.

### Sprint 4 — Core Agentic Security (Weeks 7–8)
10. **Non-Human Identity (NHI) Security Controls** 🔴
    - Agent credential tracking, scope enforcement, rotation policies
    - Behavioral anomaly detection for NHI usage

11. **Dynamic Code Execution Safety (OWASP ASI05)** 🔴
    - Sandbox enforcement for agent-generated code
    - Language allowlist, execution budgets, dangerous import blocking

### Sprint 5 — Agent Defense (Weeks 9–10)
12. **Multi-Agent Lateral Movement Detection** 🔴
    - Privilege escalation detection across agent chains
    - Task-scope drift detection and chain circuit breaker

13. **Automated Jailbreak Fuzzing Defense** 🟠
    - Continuous red-team loop (PAIR, TAP, GCG frameworks)
    - Auto-push new patterns to live threat feed

### Sprint 6 — Discovery & Scanning (Weeks 11–12)
14. **Shadow AI Detection** 🟠
    - Detect unsanctioned AI API usage per tenant
    - AI service endpoint fingerprinting

15. **Pre-Deployment Model Scanning** 🟠
    - Scan .pkl/.pt/.safetensors/.onnx/.gguf for backdoors and RCE
    - Weight hash verification against manifest

### Sprint 7 — Hardening (Weeks 13–14)
16. **Human-Agent Trust Exploitation Guard (OWASP ASI09)** 🟠
    - Confidence scoring, deception detection, mandatory review triggers

17. **Agentic Supply Chain + Cascading Failure Protection (ASI04/ASI08)** 🟠
    - Runtime tool integrity verification, plugin signature checking
    - Per-chain circuit breaker, graceful degradation

18. **SIEM Advanced Packs** 🟡
    - Splunk, Microsoft Sentinel, Elastic mapping packs
    - Dead-letter queue replay worker

19. **SSH Tunnel Manager** 🟡
    - Built-in tunnel management for remote GPU/AI services

---

## Phase 6 — Enterprise Ecosystem (Weeks 15–22)

Goal: Platform ecosystem with long-term enterprise lock-in and recurring revenue.

### Sprint 8 — Platform (Weeks 15–16)
20. **Plugin SDK + Marketplace** 🟠
    - Base plugin class with lifecycle hooks
    - Registry: install, enable, disable, update plugins

21. **Tenant Self-Service Portal** 🟠
    - Usage dashboards, security config, API key management

### Sprint 9 — Verticals (Weeks 17–18)
22. **Vertical Compliance Packs** 🟠
    - Healthcare (HIPAA PHI), Finance (PCI-DSS), Legal (privilege detection)

23. **IdP Integration Expansion (SSO)** 🟡
    - SAML 2.0, OIDC, SCIM provisioning (Okta, Azure AD, Google)

### Sprint 10 — Intelligence (Weeks 19–20)
24. **Continuous Compliance Automation** 🟡
    - Scheduled assessments, SOC 2 Type II mapping, delta reporting

25. **Model Drift / Behavioral Monitoring** 🟡
    - Output distribution baseline, semantic drift scoring, regression alerts

### Sprint 11 — Future-Proofing (Weeks 21–22)
26. **MCP Deep Security** 🔵
    - MCP server trust hierarchy, capability allowlists, spoofing detection

27. **Managed Multi-Region Hosting** 🟡
    - Railway/Oracle deploy hardening; optional managed DB beyond SQLite

---

## Final Targets

| Metric | Current (v1.0) | After Phase 6 (v2.0) |
|--------|----------------|----------------------|
| Features | 40 | 57 |
| Tests | 510 | 420+ |
| OWASP LLM Top 10 | 9/10 | 10/10 |
| OWASP Agentic Top 10 | 6/10 | 10/10 |
| EU AI Act Readiness | ~40% | ~95% |
| Deployment | Docker (Railway-ready) | Hosted multi-region |
| Revenue | None | Billing live |

---

Priority Key: 🔴 Critical/High · 🟠 High · 🟡 Medium · 🔵 Forward-looking
