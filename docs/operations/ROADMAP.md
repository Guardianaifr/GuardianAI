# GuardianAI Roadmap

**Vision**: Expand from an LLM firewall into the industry's most complete AI security control plane.  
**Current Status**: 44 features shipped · Monad Metropolis Track 04 & Sponsor Bounties Delivered (Envio HyperIndex, Category Labs Mera Passkey Enclave, Agent Middleware SDK, 166 Hard Audit Suite) · Production Go  

---

## Completed Milestones

- ✅ 33 major security feature groups
- ✅ 32 roadmap topics delivered
- ✅ Full OWASP LLM Top 10 (2025) coverage — **10/10**
- ✅ Benchmark alignment on real datasets (3,211 prompts, 8 datasets): AdvBench 99.0% strict, HarmBench 72.8% strict — see ../whitepaper/WHITEPAPER_PUBLIC.md §6 and `artifacts/evidence/definitive_benchmark_v4.json`
- ✅ **ERC-8004 Identity Registration:** canonical Trustless Agents registry integration, register-then-transfer ownership handoff, fail-closed safety gates, 42-test offline suite (../whitepaper/WHITEPAPER_PUBLIC.md Feature 39)
- ✅ **Identity Gate & Point-of-Interaction Enforcement:** pre-flight RPC relay & agentic control plane enforcement, on-chain `ownerOf` validation, database-level hot-wallet collision defense, and shadow observation mode (../whitepaper/WHITEPAPER_PUBLIC.md Feature 40)
- ✅ **GuardianPolicyGuard & Monad Parallel EVM Guardrails:** 10 Solidity invariants, EIP-712 cryptographic verification, zero-trust function selector allowlists (RBAC), rolling 24h outflow caps, and conflict-free namespaced nonces scaling to 10,000 TPS on Monad Testnet (Feature 41)
- ✅ **Agent Middleware SDK (@guardianai/middleware):** Drop-in ElizaOS memory-poisoning prevention plugin and Viem security decorator (49 TS unit tests passing) (Feature 42)
- ✅ **Envio HyperIndex Real-Time Indexer:** Multi-contract blockchain event streaming across 5 Monad contracts with sub-second GraphQL feeds and 36 passing tests (Feature 43)
- ✅ **Category Labs Mera Passkey PRF Enclave:** Sovereign, non-wallet agent identity minting (Ed25519) and zero-knowledge memory encryption (AES-256-GCM + HKDF) with active tamper tripwires (`MEMORY_POISONING_DETECTED`) (Feature 44)
- ✅ **Empirical Hard Audits on Real-World Datasets:** 166/166 hard test assertions passing (`npm run test:hard`); 1,061 live attack vectors tested across Lakera Gandalf, BIPIA, SecLists, and BLNS corpora (96.23% catch rate, 100% tamper precision, sub-0.5ms P50 latency)
- ✅ SLO verdict: all_passed = true

---

## Phase 4 — Go-to-Market

Goal: Production-ready, revenue-generating, EU-compliant.

### Track 4.0 — Urgent Compliance ✅ COMPLETE
1. ~~**EU AI Act Compliance Module**~~ ✅ **COMPLETE**
   - Risk classification (Annex III), RMS generator (Art. 9), Transparency report (Art. 13)
   - Conformity checklist (12 items), ISO 42001 QMS mapping (7 clauses)
   - 38 tests passing · CLI tool generates JSON + Markdown reports
   - Assessment result: **98% compliant, 8/8 articles passed**

2. ~~**System Prompt Leakage Protection**~~ ✅ **COMPLETE**
   - 3-layer detection: pattern matching, n-gram overlap, extraction attempt boosting
   - 23 tests passing · OWASP LLM07 covered · Integrated into output pipeline

### Track 4.1 — Auth & Revenue ✅ COMPLETE
3. ~~**JWT Authentication + RBAC**~~ ✅ **COMPLETE**
   - HS256 JWT with access/refresh tokens, 4 roles, 13 permissions
   - 6 API endpoints: login, refresh, logout, register, me, users
   - 37 tests passing · Tenant scoping · Token revocation · Auto-bootstrap

4. ~~**Sign-Off Document Completion**~~ ✅ **COMPLETE**
   - Updated all 5 sign-off documents with Phase 4 evidence, adversarial test results, benchmarks

5. ~~**Usage Metering + Billing + Pricing Tiers**~~ ✅ **COMPLETE**
   - 4 tiers: Free ($0) / Starter ($49/mo) / Pro ($299/mo) / Enterprise (custom)
   - Per-tenant daily request + token metering with SQLite persistence
   - Tier-based rate limiting, usage history, admin dashboard data
   - 29 tests passing · Thread-safe · Concurrent metering verified

### Track 4.2 — Visibility & Developer Experience ✅ COMPLETE
6. ~~**Security Dashboard & Analyst UI**~~ ✅ **COMPLETE**
   - JWT login flow, real-time WebSocket event feed, threat breakdown chart
   - Dark glassmorphism UI, stats cards, responsive layout
   - Route: `/site/dashboard` · Integrated with all backend APIs

7. ~~**Developer SDK (Python + JavaScript)**~~ ✅ **COMPLETE**
   - `from guardianai import GuardianAI` — one-liner integration
   - JWT auth, prompt scanning, response validation, OpenAI proxy, auto-retry
   - 23 tests passing · Thread-safe · Mock server test harness

### Track 4.3 — Infrastructure ✅ COMPLETE
8. ~~**Universal Auth Proxy Mode**~~ ✅ **COMPLETE**
   - Supports Ollama, LocalAI, vLLM, llama.cpp, OpenAI
   - Request translation, model allowlisting, header stripping, token bucket rate limiter
   - 28 tests passing

9. ~~**Dependency Pinning CI Gate**~~ ✅ **COMPLETE**
   - Scans requirements files, detects unpinned deps, CycloneDX SBOM generation
   - CLI tool: `python tools/check_dep_pinning.py`
   - 23 tests passing

---

## Phase 5 — Advanced Threats ✅ COMPLETE

Goal: Full OWASP Agentic Top 10 coverage, ahead of all competitors.

### Track 5.1 — Core Agentic Security ✅ COMPLETE
10. ~~**Non-Human Identity (NHI) Security Controls**~~ ✅ **COMPLETE**
    - ✅ W3C Verifiable Credentials for agents, Ed25519 issuance (`guardian/passport/credentials.py`)
    - ✅ ERC-8004 canonical agent identity & owner validation (`guardian/passport/identity_gate.py`)
    - ✅ Automated TTL-based credential rotation policies with cron scheduling (`guardian/security/credential_rotation.py`)
    - ✅ EWMA-based agent behavioral anomaly profiling — frequency spikes, new endpoint detection
    - ✅ 11 tests passing (`tests/security/test_credential_rotation.py`, `tests/test_phase5.py`)

11. ~~**Dynamic Code Execution Safety (OWASP ASI05)**~~ ✅ **COMPLETE**
    - ✅ Filesystem path permissions & sandbox rules (`guardian/runtime/filesystem_sandbox.py`)
    - ✅ Tool-call policy confirmation & dangerous AST import blocking (`guardian/guardrails/skill_scanner.py`)
    - ✅ Isolated subprocess execution sandbox with configurable CPU/memory/time limits (`guardian/runtime/execution_sandbox.py`)
    - ✅ Static AST pre-flight analysis, restricted builtins, platform-aware resource enforcement
    - ✅ 11 tests passing (`tests/test_phase5.py`)

### Track 5.2 — Agent Defense ✅ COMPLETE
12. ~~**Multi-Agent Lateral Movement Detection**~~ ✅ **COMPLETE**
    - ✅ Parent→child hop authorization & max hop limits (`guardian/security/agentic_controls.py`)
    - ✅ Task-scope tool allowlist & non-escalation hierarchy enforcement
    - ✅ Agent execution kill-switch & global pause control
    - ✅ Cross-agent graph drift tracker with adjacency matrix, density analysis, hub detection, and cycle detection (`guardian/security/agent_graph_tracking.py`)
    - ✅ 8 tests passing (`tests/test_phase5.py`)

13. ~~**Automated Jailbreak Fuzzing Defense**~~ ✅ **COMPLETE**
    - ✅ Automated adversarial fuzzing loop (PAIR, TAP, GCG mutation strategies in `guardian/security/jailbreak_fuzzer.py`)
    - ✅ Automated hot-patching of missed variants into live threat feed
    - ✅ Unit tests passing (`tests/security/test_jailbreak_fuzzer.py`)

### Track 5.3 — Discovery & Scanning ✅ COMPLETE
14. ~~**Shadow AI Detection**~~ ✅ **COMPLETE**
    - ✅ 17 AI provider endpoint detection (OpenAI, Anthropic, Azure OpenAI, AWS Bedrock, Cohere, HuggingFace, Google AI, Replicate, Mistral, Together, Perplexity, Groq, DeepSeek, AI21, Cerebras, Fireworks, Ollama) (`guardian/security/shadow_ai.py`)
    - ✅ URL + header-based detection (x-anthropic-version, x-goog-api-key, Bearer token patterns)
    - ✅ Per-tenant alert generation, stats aggregation, and provider allowlisting
    - ✅ 14 tests passing (`tests/test_phase5.py`)

15. ~~**Pre-Deployment Model Scanning**~~ ✅ **COMPLETE**
    - ✅ Model provenance verification against signed manifest with weight SHA-256 (`guardian/security/supply_chain.py`)
    - ✅ CycloneDX SBOM generation with strict dependency and model provenance gating
    - ✅ Deep binary scanner for .pkl/.pt/.safetensors/.onnx/.gguf deserialization exploits (`guardian/security/model_scanner.py`)
    - ✅ Pickle opcode analysis (REDUCE, GLOBAL, INST, BUILD, STACK_GLOBAL, NEWOBJ), PyTorch zip analysis, safetensors header injection, ONNX custom ops, GGUF metadata validation
    - ✅ 14 tests passing (`tests/test_phase5.py`)

### Track 5.4 — Hardening ✅ COMPLETE
16. ~~**Human-Agent Trust Exploitation Guard (OWASP ASI09)**~~ ✅ **COMPLETE**
    - ✅ Real-time confidence scoring & deception detection (`guardian/security/trust_exploitation.py`)
    - ✅ Mandatory review triggers & phishing URL/address poisoning blockers
    - ✅ Unit and load stress tests passing (`tests/security/test_trust_exploitation.py`, `tests/stress/test_trust_exploitation_load.py`)

17. ~~**Agentic Supply Chain + Cascading Failure Protection (ASI04/ASI08)**~~ ✅ **COMPLETE**
    - ✅ AST skill scanner for blocked imports and sensitive calls (`guardian/guardrails/skill_scanner.py`)
    - ✅ Release manifest signing & cryptographic verification (`guardian/security/supply_chain.py`)
    - ✅ Dual-layer circuit breakers: smart contract (`GuardianCircuitBreaker.sol`) & agentic control plane (`agentic_controls.py`)

18. ~~**SIEM Advanced Packs**~~ ✅ **COMPLETE**
    - ✅ Real-time SIEM async streaming router with CEF/JSON format and dead-letter queue (`backend/siem.py`)
    - ✅ Microsoft Sentinel CommonSecurityLog mapper with KQL detection rules (`guardian/siem/mapping_packs.py`)
    - ✅ Elastic ECS mapper with Kuery detection rule templates (`guardian/siem/mapping_packs.py`)
    - ✅ DLQ replay daemon with exponential backoff, max retry thresholds, and FATAL drop logging (`guardian/siem/dlq_replay.py`)
    - ✅ 11 tests passing (`tests/test_phase5.py`)

19. ~~**SSH Tunnel Manager**~~ ✅ **COMPLETE**
    - ✅ Built-in tunnel management for remote GPU/AI services (`guardian/utils/ssh_manager.py`)
    - ✅ Process lifecycle monitoring, health checks, and graceful teardown (`tests/test_ssh_manager.py`)

---

## Phase 6 — Enterprise Ecosystem

Goal: Platform ecosystem with long-term enterprise lock-in and recurring revenue.

### Track 6.1 — Platform
20. **Plugin SDK + Marketplace** 🟠 **TO DO**
    - ⏳ Base plugin class with lifecycle hooks
    - ⏳ Registry: install, enable, disable, update plugins

21. **Tenant Self-Service Portal** 🟢 **PARTIALLY COMPLETE**
    - ✅ Dark/glassmorphism analyst dashboard live (`/site/dashboard`)
    - ✅ Usage metering, tier display, and real-time threat feed
    - ⏳ Self-service API key provisioning & tenant security config editor UI

### Track 6.2 — Verticals
22. **Vertical Compliance Packs** 🟢 **PARTIALLY COMPLETE**
    - ✅ Healthcare HIPAA PHI extraction & validation benchmark harness (`tools/run_pii_hipaa_benchmark.py`)
    - ⏳ Finance (PCI-DSS) & Legal (attorney-client privilege detection) packs

23. **IdP Integration Expansion (SSO)** 🟢 **PARTIALLY COMPLETE**
    - ✅ Provider-aware IdP revocation contracts for Okta, Auth0, Azure AD (`guardian/security/idp_revocation.py`)
    - ✅ OIDC discovery cache & full JWT exp/nbf/iss/aud validation
    - ⏳ SAML 2.0 & SCIM user provisioning

### Track 6.3 — Intelligence
24. **Continuous Compliance Automation** ✅ **COMPLETE**
    - ✅ Scheduled audit scanner background service with persistent JSON history (`guardian/audit/scheduler.py`)
    - ✅ Automatic passing badges & webhook notifications
    - ✅ Formal mappings to SOC 2 Type II, ISO 42001, and EU AI Act (`artifacts/assurance/FRAMEWORK_CONTROL_MAPPING.md`)

25. **Model Drift / Behavioral Monitoring** 🟡 **TO DO**
    - ⏳ Output distribution baseline, semantic drift scoring, regression alerts

### Track 6.4 — Infrastructure & Web3 Security
26. **MCP Deep Security** ✅ **COMPLETE**
    - ✅ MCP server trust hierarchy & header enforcement (`guardian/security/agentic_controls.py`)
    - ✅ Per-server tool capability allowlists & untrusted server blocking
    - ✅ Unit tests passing in runtime and security suites

27. **Managed Multi-Region Hosting** 🟢 **PARTIALLY COMPLETE**
    - ✅ Production Docker containerization, Railway deployment configuration, and hardening
    - ⏳ Multi-region managed database cluster (PostgreSQL transition from single-writer SQLite)

---

## Final Targets & Current Posture

| Metric | Current Status | Target (Full Release) |
|--------|----------------|-----------------------|
| Features | 50 shipped | 57 |
| Tests Passing | 1,722+ | 1,500+ |
| OWASP LLM Top 10 | 10/10 (100%) | 10/10 (100%) |
| OWASP Agentic Top 10 | 10/10 (100%) | 10/10 (100%) |
| EU AI Act Readiness | 98% (8/8 articles passed) | 98%+ |
| Deployment | Docker (Railway-ready) | Hosted multi-region |
| Revenue / Billing | Metering & 4 pricing tiers live | Production Stripe live |

---

Status Key: ✅ Complete · 🟢 Partially Complete · 🟡 In Progress / Moderate Effort · 🟠 Planned · 🔴 Critical Pending
