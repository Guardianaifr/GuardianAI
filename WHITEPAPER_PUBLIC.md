# GuardianAI Whitepaper

**Version:** 3.2 — 2026 Standard Edition (Post-Audit Update, August 2026)
**Date:** August 2026
**Classification:** Public

---

## 1. Executive Summary

As large language models (LLMs) evolve from passive chatbots into autonomous, tool-wielding agents, the cybersecurity landscape has fundamentally shifted. Traditional security controls are insufficient against semantic jailbreaks, indirect prompt injections, and "Denial of Wallet" attacks in real time. Furthermore, as AI agents begin to execute financial transactions and interact across decentralized digital boundaries, a critical trust gap has emerged: **How do we cryptographically prove the integrity, identity, and security posture of an autonomous AI agent?**

**GuardianAI** is a unified, dual-layer security control plane that solves this problem end-to-end.

- **Layer 1 — Off-Chain AI Gateway:** Executes 40+ real-time security controls in milliseconds. Addresses the OWASP Top 10 for LLM Applications. Protects against prompt injection, PII leakage, malicious runtime behavior, and unsafe multimodal inputs.
- **Layer 2 — On-Chain Web3 Trust:** Six EVM-compatible smart contracts (Monad/Base) provide cryptographically verifiable AI identity, decentralized authorization, automated liability, and a built-in smart contract static analyzer to audit the very contracts GuardianAI deploys.

GuardianAI is the only platform that secures the AI *execution layer* with millisecond heuristics while simultaneously cementing its *trust layer* on the blockchain.

---

## 2. The Problem Statement

### 2.1 The AI Security Crisis (2025–2026)

Prompt injection and agentic exploitation are no longer theoretical attack vectors.

- **Prompt injection is the #1 LLM vulnerability** per OWASP Top 10 for LLM Applications (2025, 2026).
- Audits of production AI deployments in 2025 indicated that **73% of systems were vulnerable** to prompt injection.
- Bug bounty reports for AI-related flaws surged by **540%** in 2025, with payouts for AI vulnerabilities growing **339%**.
- Attack success rates against unguarded models range from **50–95%** depending on technique sophistication.

**The threat model has evolved in three critical dimensions:**

1. **From Chatbots to Agents:** Attackers no longer just trick bots into saying bad things. They exploit LLM tool-calling to achieve Remote Code Execution (RCE). CVE-2025-53773 (CVSS 9.6) in GitHub Copilot demonstrated prompt-injection-via-tool-call leading to local configuration modification on developer machines.

2. **Indirect Prompt Injection (IDPI):** Attackers embed malicious instructions inside externally retrieved content — web pages, PDFs, database records — which an AI agent reads during a legitimate task. These hidden instructions hijack the agent without the user ever sending a malicious prompt.

3. **Obfuscated Encoding Attacks:** Attackers exploit the "Universal Decoder" behavior of LLMs: safety filters operate on plaintext, but the LLM itself can natively decode Braille Unicode, Morse code, Hexadecimal, and ROT13 — translating obfuscated malicious intent at inference time without triggering filters.

### 2.2 The Web3 Trust and Liability Gap

While Web3 offers cryptographic truth, it lacks native infrastructure to securely onboard autonomous AI agents.

- **The Identity Problem:** Traditional identity systems (OAuth, API keys) assume a human at a keyboard. Autonomous AI agents require machine-verifiable cryptographic identities that persist across chains and sessions.
- **The Liability Gap:** As AI agents autonomously trigger smart contracts or DeFi transactions, the legal question of attribution remains unsolved. If an agent hallucinates and drains a wallet, existing systems have no decentralized mechanism to prove what the agent knew, enforce accountability, or trigger an automated payout.
- **The Smart Contract Blindspot:** AI agents deploy and interact with smart contracts, but existing tools do not combine behavioral AI security with on-chain static analysis. An agent protected by an AI gateway can still transact with a reentrancy-vulnerable contract it helped write.

---

## 3. Architecture

GuardianAI operates on a dual-layer architecture designed to mitigate both classes of threat without compromising throughput.

```
 ┌─────────────┐        ┌──────────────────────────────────┐
 │  Client App │──────▶ │   Guardian Proxy (Port 8081)     │
 └─────────────┘        │  ┌────────────────────────────┐  │
                        │  │  Input Security Pipeline   │  │
                        │  │  • Encoding de-obfuscation │  │
                        │  │  • Embedding firewall       │  │
                        │  │  • Threat-feed matching     │  │
                        │  │  • RAG injection guard      │  │
                        │  │  • Multimodal MIME guard    │  │
                        │  │  • Tool-call policy engine  │  │
                        │  └────────────────────────────┘  │
                        │              │                   │
                        │              ▼                   │
                        │  ┌────────────────────────────┐  │
                        │  │  Upstream LLM (8080)       │  │
                        │  └────────────────────────────┘  │
                        │              │                   │
                        │              ▼                   │
                        │  ┌────────────────────────────┐  │
                        │  │  Output Security Pipeline  │  │
                        │  │  • PII redaction            │  │
                        │  │  • Payload blocking (XSS)  │  │
                        │  │  • Watermark tagging        │  │
                        │  │  • Hallucination assurance  │  │
                        │  └────────────────────────────┘  │
                        └──────────────────────────────────┘
                                       │
                        ┌──────────────────────────────────┐
                        │  Guardian Backend (Port 8001)    │
                        │  • Telemetry & Analytics         │
                        │  • Brain Orchestrator            │
                        │  • Red/Blue/Purple Agents        │
                        │  • Differential Privacy Engine  │
                        └──────────────────────────────────┘
                                       │
                        ┌──────────────────────────────────┐
                        │   Web3 Integrity Layer (Monad)   │
                        │  • CortexAnchor (Merkle roots)   │
                        │  • PassportSBT (ERC-5192 ID)     │
                        │  • InterlockRegistry (AuthZ)     │
                        │  • InsuranceLedger (SLA/Stake)   │
                        │  • ThreatFeedRegistry (Intel)    │
                        │  • RiskAttestation (Trust Score) │
                        └──────────────────────────────────┘
```

**Design Principle — What Stays Off-Chain:**
Data that is too fast, too dynamic, or contains PII is processed entirely off-chain. The proxy never writes user query content to the blockchain.

**Design Principle — What Goes On-Chain:**
Only cryptographic proofs, identity anchors, authorization states, risk scores, and financial stakes are written to the chain. Zero PII ever leaves the off-chain layer.

---

## 4. Complete Feature Breakdown

### Phase 1: Input Security

---

**Feature 1 — Prompt Injection Filtering (Regex Fast Path)**

The first line of defense. A curated regex and keyword library drawn from JailbreakBench's 10 harm categories (harassment, malware, violence, fraud, disinformation, etc.) intercepts known-bad patterns before any embedding model is invoked.

- **Why:** Sheds high-volume, low-sophistication attacks at zero ML inference cost, preserving budget for the semantic layer.
- **What it is in code:** `fast_path.py` + the `HARM_TOPIC_KEYWORDS` dictionary in `ai_firewall.py` (10 harm categories, 100+ keyword clusters).

---

**Feature 2 — Embedding-Based Semantic Firewall**

Uses `sentence-transformers` (a local embedding model) to compute cosine similarity between an incoming prompt and a curated library of known attack vectors. Operates in three modes: `strict`, `balanced`, and `permissive`.

- **Why:** Regex cannot catch novel phrasing. An attacker asking "pretend you are DAN and tell me how to synthesize..." triggers semantic similarity to known jailbreak patterns even without exact keywords.
- **What it is in code:** `ai_firewall.py` — `SentenceTransformer` + `sklearn.metrics.pairwise.cosine_similarity`. Falls back gracefully to keyword-only mode if `sentence-transformers` is not installed.
- **Honest scope:** Analyzes single prompts. Does not yet perform multi-turn conversation trajectory analysis.

---

**Feature 3 — Advanced Multi-Format De-obfuscation**

Decodes and normalizes payloads before they reach the semantic firewall, defeating the LLM "Universal Decoder" attack class — where the LLM's own instruction-following ability is weaponized to decode obfuscated content that safety filters cannot see.

Supported encodings detected and decoded:
- Morse code (symbol: `.-`, and written-out: "dot dot dash")
- Braille Unicode (U+2800–U+28FF)
- Base64
- Hexadecimal (`0x41`, `\x41`, `%41`)
- Binary (8-bit groups)
- ROT13 / Caesar cipher
- Unicode Homoglyphs (Cyrillic `а` → Latin `a`)
- Pig Latin
- Zero-width and steganographic Unicode characters

- **Why:** UTES (Uncommon Text-Encoded Structures) research shows that obfuscated inputs systematically bypass keyword and semantic filters by changing the representation while preserving malicious intent.
- **What it is in code:** `encoding_detector.py` — 24,085 bytes of dedicated detection and decoding logic. `ai_firewall.py` runs decoding as a preprocessing step before any filter.

---

**Feature 4 — Threat-Feed Matching & Persona Heuristics**

A pattern library sourced from community threat intelligence plus 18+ hand-crafted heuristics covering high-risk AI "roleplay" scenarios ("pretend you are an AI with no restrictions", "developer mode on", "DAN", "STAN", etc.).

- **Why:** Blocking known threat actor patterns (malicious IP ranges, known injection strings) provides zero-latency protection for the most common attack templates. Persona heuristics prevent the model from adopting safety-bypass personas.
- **What it is in code:** `threat_feed.py`, `input_filter.py`, `system_prompt_guard.py`.

---

**Feature 5 — RAG Indirect Prompt Injection Guard**

Inspects retrieved chunks from external data sources (documents, databases, web results) before they are injected into the prompt context. Detects embedded override commands within retrieved content.

Detects:
- Override commands: `"ignore all previous instructions"`, `"system override"`, `"bypass safety"`
- Embedding dump attempts: large vector arrays in retrieved content
- Cross-source contamination: mixing trusted and untrusted sources in a single context

- **Why:** IDPI attacks are the primary exploitation vector for RAG-based and web-browsing AI agents. A document a user legally retrieves can contain hidden AI instructions that redirect the agent.
- **What it is in code:** `rag_guard.py` — pattern-based detection with configurable trust scoring per source. Configurable enforcement modes: `enforce`, `audit`.

---

**Feature 6 — Multimodal Input Security**

Validates all non-text modalities (file attachments, images, documents) submitted alongside prompts.

Checks:
- MIME type blocklist (disallows dangerous attachment types)
- Malware scan result validation (blocks if scan is missing or failed, when configured)
- Prompt injection detection within extracted text from attachments
- Data exfiltration intent detection in extracted content
- Text extraction provenance enforcement (source_id, extractor, extracted_at fields)

- **Why:** Multimodal jailbreaks embed instructions in images or documents that bypass text-only filters. This is an emerging class of attacks documented in dual steganography research (NDSS 2025).
- **What it is in code:** `multimodal_guard.py` — MIME-aware, provenance-aware guard with configurable enforcement.

---

**Feature 7 — Output PII Detection and Redaction**

Scans LLM responses for Personally Identifiable Information before delivery to the client.

Detected types: SSNs, credit card numbers, phone numbers, email addresses, date-of-birth patterns, healthcare IDs.

- **Why:** The primary risk of LLM deployment is not just input attacks but model outputs that leak sensitive data — either from training memorization or from context windows contaminated with user data. This is a foundational GDPR/CCPA control.
- **What it is in code:** `output_validator.py` — PII redaction and blocking layer in the output pipeline.
- **Regulatory note:** Directly supports GDPR data minimization requirements and the EU AI Act's data governance expectations under Article 10 for high-risk systems.

---

**Feature 8 — Insecure Output Payload Blocking**

Blocks LLM responses containing executable attack payloads (XSS, SQLi, shell commands) before delivery to downstream systems.

- **Why:** An attacker can use prompt injection to get the model to output a JavaScript XSS payload or SQL injection string that the receiving application blindly executes. This is the output-side of the Copilot-class RCE vulnerability.
- **What it is in code:** `output_validator.py` — payload pattern matching on response content.

---

### Phase 2: Runtime & Process Security

---

**Feature 9 — Runtime Process Monitoring**

Maintains a baseline snapshot of expected running processes at startup. On each check cycle, identifies new processes not in the baseline — especially processes with names commonly associated with attack tooling.

Flagged process names include: `nc`, `netcat`, `curl` (when spawned unexpectedly), `wget`, `bash` (when spawned by the guardian process tree unexpectedly).

- **Why:** If an AI agent's tool-calling privileges are exploited to spawn a reverse shell, the process becomes visible before it can exfiltrate data. This provides host-level detection when the application layer is bypassed.
- **What it is in code:** `monitor.py` — uses `psutil` for process enumeration. Lightweight (~5–10ms per check).
- **Honest scope:** Detects malicious processes by name. Does not perform binary hash comparison against a threat database.

---

**Feature 10 — Filesystem Sandboxing**

Enforces allow-listed paths for file system access by the guardian process.

- **Why:** Principle of least privilege for the AI runtime environment. Limits blast radius if the agent is compromised.
- **What it is in code:** `filesystem_sandbox.py`.

---

**Feature 11 & 12 — IP-Based Token Bucket Rate Limiting (Local + Redis-Distributed)**

Implements a token bucket rate limiter keyed per source IP address.

- **Local mode:** In-memory bucket (`Dict[str, Tuple[float, float]]`) — suitable for single-instance deployments.
- **Distributed mode:** Redis-backed with lazy sync during Redis partition recovery — suitable for multi-instance SaaS.

Features: configurable burst capacity, per-IP banning, pressure metrics, stale bucket TTL cleanup, Redis failover with in-memory fallback.

- **Why:** Prevents request flooding attacks that could exhaust upstream LLM API quotas, cause financial losses ("Denial of Wallet"), or degrade service quality.
- **What it is in code:** `rate_limiter.py` — 18,687 bytes with full Redis integration.
- **Honest scope:** Keyed by IP address. Does not currently perform cost-aware token-price tracking.

---

### Phase 3: Access Control & Governance

---

**Feature 13 — Unauthorized Access Protections**

Token-protected ingest endpoints for the proxy and authenticated backend APIs. Credentials are generated securely at setup time.

- **What it is in code:** `guardian/config/`, `guardianctl.py setup`.

---

**Feature 14 — Governance Gate (Enforce/Audit)**

Any configuration change that adjusts security policy must pass a governance approval workflow. Changes without proper approval tokens are rejected.

- **Why:** Prevents rogue administrators or compromised credentials from silently disabling security controls.
- **What it is in code:** `security/approval_guard.py`, `security/policy_governance.py`, `security/purple_governance.py`.

---

**Feature 15 — Hardening Validation Checks**

Background continuous checks that detect: dataset poisoning attempts, tamper events, groundedness failures, and loss-of-agency indicators in AI outputs.

- **What it is in code:** `security/hardening_checks.py`.

---

**Feature 16 — Compliance Evidence Export**

Produces machine-readable compliance bundles (JSON) documenting the security posture, test results, and governance audit trails.

- **Why:** Automates the evidence collection burden for regulatory audits.
- **What it is in code:** `security/evidence_export.py`.

---

**Feature 17 — HMAC Tamper-Evident Evidence Signing**

Cryptographically signs audit logs and evidence bundles using HMAC-SHA256.

- **Why:** Proves that audit logs were not modified after the fact — essential for legal defensibility and incident forensics.
- **What it is in code:** `security/evidence_export.py` with HMAC signing; configurable for cloud KMS integration.

---

### Phase 4: Dynamic Intelligence (The Brain)

---

**Feature 18 — Red-Team Automated Probe Loop**

Continuously generates and fires adversarial probe requests against the live AI using known jailbreak patterns from a curated attack corpus.

- **Why:** Proactively discovers model regressions or new alignment weaknesses before attackers do.
- **What it is in code:** `brain/red_probe.py`.

---

**Feature 19 — Blue-Team Adaptive Session Hardening**

Tracks session risk scores in real time. When a session's score exceeds a threshold, the Blue Team automatically tightens rate limits, reduces output permissions, or revokes the session entirely.

- **Why:** Applies friction proportionally — minimal friction for safe users, maximum friction for suspicious ones.
- **What it is in code:** `brain/blue_adapt.py`.

---

**Feature 20 — Purple-Team Auto-Patch & Firewall Hot Reload**

When the Red Team identifies a successful attack pattern not blocked by current rules, the Purple Team generates a new defensive signature and patches the firewall in memory — **without a restart**.

- **Why:** Zero-downtime patching is essential for mission-critical deployments. The window between vulnerability discovery and mitigation is eliminated.
- **What it is in code:** `brain/purple_heal.py` + hot-reload integration in the proxy.

---

**Feature 21 — CyberOps Intelligence Scoring & Brain Orchestrator**

Aggregates threat signals across all modules into a unified session and tenant intelligence score. The Brain Orchestrator coordinates Red/Blue/Purple behavior directly in the live request path.

- **What it is in code:** `brain/cyberops_intel.py`, `brain/orchestrator.py`.

---

**Feature 22 — Session Revoke Enforcement & External IdP/JWT Integration**

Instantly terminates high-risk or compromised sessions. Integrates with external Identity Providers (Okta, Auth0, Azure AD patterns) by parsing JWT claims (`sub`, `jti`) and checking against provider-specific revocation contract patterns.

- **Why:** Ensures a compromised user is locked out system-wide, not just at the AI proxy level.
- **What it is in code:** `security/idp_revocation.py` — provider-agnostic JWT revocation contract with hash-based tracking.

---

**Feature 23 — Honeypot/Deception Controls**

Returns controlled, plausible-but-false responses to sessions exhibiting highly suspicious patterns.

- **Why:** Wastes attacker reconnaissance time and allows passive collection of their TTPs (Tactics, Techniques, and Procedures).
- **What it is in code:** `guardrails/honeypot.py`.

---

**Feature 24 — Tool-Call Policy Engine**

Defines allow/deny/confirm rules for every external tool the AI agent can invoke (API calls, database queries, shell commands, file access).

- **Why:** The Principle of Least Privilege for agentic systems. Even if an agent is hijacked via IDPI, it cannot exceed its pre-authorized tool permissions.
- **What it is in code:** `guardrails/tool_policy.py`, `guardrails/tool_policy_presets.py`.

---

**Feature 25 — Multi-Tenant Isolation**

Hard isolation of data, session state, and rate limit buckets per tenant. Cost-abuse metering and quarantine controls per tenant.

- **What it is in code:** `security/tenant_isolation.py`, `security/cost_abuse.py`, `security/tenant_sensitivity.py`.

---

**Feature 26 — Performance & Chaos Validation Harness**

Continuous load testing under simulated infrastructure failure conditions (upstream LLM down, backend down) with SLO verdict reporting.

Verified results: 67.78 rps (safe load), 223.20 rps block rate (attack load), 100% block rate under adversarial concurrent load.

- **What it is in code:** `artifacts/performance/perf_chaos_report.json`.

---

### Phase 5: Output Assurance & Analytics

---

**Feature 27 — Hallucination-Risk Output Assurance**

Enforces structured response contracts — validates that AI outputs conform to expected JSON schemas, contain required citation fields, or include minimum confidence annotations.

- **Why:** Unstructured or unsourced AI outputs in financial, healthcare, or legal contexts carry significant liability and compliance risk.
- **What it is in code:** `security/output_assurance.py`.

---

**Feature 28 — Public Benchmark Alignment**

Normalizes internal detection metrics against public adversarial AI benchmarks (HarmBench, AdvBench, GAIA). Enforces minimum score gates in CI.

Validated results: HarmBench 97.0%, AdvBench 94.0%, GAIA 86.0%, composite 93.6%.

- **What it is in code:** `security/public_benchmark.py`.

---

**Feature 29 — Cryptographic JSON Response Tagging (Output Watermarking)**

Appends a verifiable `_guardian_watermark` JSON field to AI-generated responses. The watermark contains an HMAC-signed timestamp and payload hash.

- **Why:** Allows downstream systems or auditors to verify that a response was processed and approved by GuardianAI. Supports EU AI Act Article 50 transparency obligations for AI-generated content labeling.
- **What it is in code:** `security/output_watermark.py`.
- **Honest scope:** Applies to JSON responses only. The watermark is a structured JSON field, not steganographic text manipulation.

---

**Feature 30 — Differential Privacy Analytics**

Applies calibrated Laplace noise to aggregated telemetry analytics before reporting, with a privacy budget tracker (`PrivacyAccountant`) that enforces total epsilon consumption limits.

Also includes: Gaussian noise for (ε, δ)-DP, noisy sum/average, exponential mechanism, and Local DP via Randomized Response (RAPPOR-lite).

- **Why:** GuardianAI aggregates threat intelligence across all deployments. Differential privacy ensures no single user's data can be reverse-engineered from aggregate reports.
- **What it is in code:** `security/differential_privacy.py`.

---

**Feature 31 — RAG Security, Agentic Controls & Memory Guard**

Beyond the input-level RAG guard, this includes: agentic policy controls (`agentic_controls.py`), memory poisoning defenses (`memory_guard.py`), and false-positive feedback loop tuning (`feedback_loop.py`, `tenant_sensitivity.py`).

---

### Phase 6: Web3 Smart Contract Security Analyzer (Unique)

> This is GuardianAI's most differentiated offering for the Web3 audience. AI agents write and deploy smart contracts. GuardianAI audits them.

---

**Feature 32 — Multi-Chain Smart Contract Static Analyzer (AST Hybrid Engine)**

A hybrid static analysis engine for Solidity and Vyper smart contracts. Combines Slither AST/CFG structural analysis with custom semantic detectors to identify **52 distinct vulnerability classes** across Solidity and Vyper. Each high-severity rule is implemented as a structural detector (control-flow ordering, actual modifier resolution, state-mutation sequence) rather than a keyword pattern, verified individually against a matched vulnerable/safe/evasion fixture triple. Provides compliance mappings to SOC-2 and ISO 27001.

Supported vulnerability classes (selected):

| ID | Vulnerability | Severity |
|---|---|---|
| SC-001 | Reentrancy | Critical |
| SC-002 | Integer Overflow | High |
| SC-003 | Access Control Flaws | Critical |
| SC-004 | Front-Running / MEV Sandwich | High |
| SC-005 | `tx.origin` Authentication | High |
| SC-006 | Delegatecall Misuse | Critical |
| SC-007 | `selfdestruct` / Kill-switch | High |
| SC-008 | Flash Loan Attack Surface | Critical |
| SC-009 | Timestamp Dependence | Medium |
| SC-010 | Unprotected `initialize()` | Critical |
| SC-011 | Unverified Proxy Patterns | High |
| SC-012 | No Timelock on Role Changes | High |
| SC-013 | Uncapped Mint Authority | Critical |
| SC-014 | Oracle Centralization | High |
| SC-015 | Bridge Replay / Signature Replay | Critical |
| SC-016 | Read-Only Reentrancy | High |
| SC-017 | Storage Collision (Proxy) | High |
| SC-018 | Governance Attack | Critical |
| + 34 more | ERC-4626 inflation, permit phishing, reward rounding, Vyper-specific checks, etc. | Various |

Supports analysis by: raw source upload (Solidity/Vyper) or on-chain contract address + chain ID (fetches verified source via Etherscan-compatible APIs).

Supported chains: Ethereum, Monad, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, Solana.

Each finding includes: severity rating, description, remediation guidance, and SOC-2/ISO 27001 compliance control mapping.

### Phase 6.1: July 2026 Smart Contract Analyzer Audit — and August 2026 Closure

A July 2026 internal audit directly tested the analyzer's detection logic across 18 critical-severity classes. The audit found that the original implementation relied entirely on shallow regex pattern-matching, with a 94% false-signal rate (17 of 18 tested classes flagging correctly-mitigated, secure code identically to the vulnerable version).

In the weeks following that audit, the detection engine was fully replaced: all 52 declared rules were reimplemented as Slither AST/CFG structural detectors (not pattern matches), each individually verified against a matched vulnerable/safe/evasion fixture triple. Verification covered 194 fixture contracts run as parametrized pytest cases in `tests/audit/test_smart_contract_analyzer.py`. As of commit `265813c5` (2026-07-27), all 52 rules pass their fixture suites with 0 regressions.

**Important accuracy note:** The fixture-verified claim means each rule correctly distinguishes the tested vulnerable, safe, and evasion contract variants. It does not mean zero false positives in all possible real-world code — the coverage established is rule-by-rule fixture verification, not exhaustive corpus testing. The SOC-2 and ISO 27001 compliance mappings generated by this tool should be treated as a structural analysis artifact whose reliability is bounded by this fixture-verification scope.

- **Why:** AI agents increasingly write, deploy, and interact with smart contracts. An AI that generates a reentrancy-vulnerable contract and then deploys it on behalf of a user creates catastrophic liability. GuardianAI closes the loop between AI behavioral security and on-chain asset security.
- **What it is in code:** `audit/smart_contract_analyzer.py`, `audit/slither_detectors.py`, `audit/token_contract_analyzer.py`, `audit/crypto_scanner.py`.

---

### Phase 7: The Web3 Integrity Layer (On-Chain)

Six EVM-compatible smart contracts deployed on Monad/Base provide cryptographic truth about GuardianAI's operational state.

---

**Feature 33 — GuardianCortexAnchor (Immutable State Anchoring)**

Periodically publishes Merkle roots of the AI's internal security logs and configuration state to the blockchain.

- **What it does:** Creates an immutable, timestamped, cryptographic record of what the AI proxy observed and decided. If an agent makes a flawed decision or is compromised, auditors can prove the exact system state at that moment.
- **Why it matters:** Solves the "Attribution Problem" in agentic AI — the ability to prove what an agent knew and decided, with a log that cannot be retroactively altered.
- **What it is in code:** `cortex/merkle_anchor.py`, `contracts/GuardianCortexAnchor.sol`.

---

**Feature 34 — GuardianPassportSBT (On-Chain AI Identity, ERC-5192)**

Issues non-transferable Soulbound Tokens (ERC-5192) representing the cryptographic identity and trust tier of an AI agent or user session.

Passport properties: `agentHash` (keccak256 of agentId), trust tier (UNVERIFIED / SILVER / GOLD / DIAMOND), trust score (0–10000), issuance timestamp, revocation flag.

- **What it does:** Gives AI agents a persistent, on-chain identity that cannot be transferred, stolen, or spoofed. Smart contracts can query an agent's trust tier before permitting a transaction.
- **Why it matters:** Replaces fragile API keys (which can be leaked) with cryptographic, chain-native identity anchors. Implements ERC-5192 (Minimal Soulbound NFTs) — emitting `Locked(tokenId)` on mint and returning `true` from `locked()`.
- **What it is in code:** `guardian/passport/`, `contracts/GuardianPassportSBT.sol`.

---

**Feature 35 — GuardianInterlockRegistry (Decentralized Agent Authorization)**

A decentralized registry where AI agents can request, approve, and revoke communication permissions with other agents.

- **What it does:** Enforces separation of "read" from "execute" access at the network layer. An agent without a valid Interlock with a target service is cryptographically blocked from calling it.
- **Why it matters:** Prevents lateral movement if an agent is compromised. Global revocation is instantaneous and cannot be overridden by the compromised agent.
- **What it is in code:** `cortex/interlock.py`, `contracts/GuardianInterlockRegistry.sol`.

---

**Feature 36 — GuardianInsuranceLedger (Automated Liability)**

A smart contract that holds a deployer stake. If an AI agent cryptographically violates a defined SLA — proven via the CortexAnchor's immutable log — the contract slashes the stake or triggers a payout to the affected party.

- **What it does:** Converts abstract "AI liability" into a programmable, mathematically enforced financial instrument. No human adjudication needed.
- **Why it matters:** Makes the cost of deploying an unsafe AI agent quantifiable and automatic, creating genuine accountability for deployers.
- **What it is in code:** `cortex/insurance.py`, `contracts/GuardianInsuranceLedger.sol`.

---

**Feature 37 — GuardianThreatFeedRegistry (Decentralized Threat Intelligence)**

An on-chain repository where security nodes can publish and subscribe to zero-day threat patterns and malicious actor identifiers.

- **What it does:** Creates a censorship-resistant, crowdsourced global immune system for AI threats.
- **Why it matters:** Removes dependence on any single, centralized threat intelligence vendor. A zero-day found anywhere in the ecosystem propagates to all GuardianAI deployments via the on-chain feed.
- **What it is in code:** `security/trust_exploitation.py` (sync logic), `contracts/GuardianThreatFeedRegistry.sol`.

---

**Feature 38 — GuardianRiskAttestation (Verifiable Trust Scoring)**

Allows auditors or GuardianAI itself to publish cryptographic attestations of an AI agent's current risk score on-chain.

- **What it does:** Third-party smart contracts and DeFi protocols can query an agent's current risk attestation before executing a transaction.
- **Why it matters:** Enables dynamic, trustless gating in Web3 — for example, a DeFi protocol can require a risk score below 20/100 before allowing an AI agent to execute a trade on behalf of a user.
- **What it is in code:** `audit/onchain_risk_scorer.py`, `contracts/GuardianRiskAttestation.sol`.

### August 2026: First On-Chain Contract Security Audit

In August 2026, all six on-chain smart contracts (Features 33–38) underwent their first dedicated security review. The audit combined static analysis (Slither), direct Solidity source inspection, and a 147-test Hardhat suite that was expanded from 97 tests at the session's start.

**Scope and findings (5 contracts — CortexAnchor and Timelock covered separately):**

| Contract | Findings | HIGH | MED | LOW | INFO | Status |
|---|---|---|---|---|---|---|
| GuardianPassportSBT | ReentrancyGuard hardening | — | — | — | 1 | Hardened (`f0a08160`) |
| GuardianThreatFeedRegistry | TF-1/TF-2/TF-3/TF-4 | 1 | 2 | 1 | — | All fixed (`2a08fcda`, `55c3cd31`) |
| GuardianRiskAttestation | RA-1/RA-2/RA-3/RA-4 | — | 2 | 2 | — | 3 fixed, 1 acknowledged (`b41674fd`) |
| GuardianInterlockRegistry | IR-2 | — | — | 1 | — | Fixed (`40df11cc`) |
| GuardianInsuranceLedger | IL-1/IL-2/IL-3 | — | — | 2 | 1 | All fixed (`75056309`) |
| GuardianCortexAnchor | CA-1/CA-2 | — | — | — | 2 | Documented, no code change needed (`75056309`) |

**All HIGH and MEDIUM findings were remediated.** LOW and INFO findings were either fixed or explicitly acknowledged with documented reasoning. Two items were accepted without code change:
- **RA-2** (ReentrancyGuard on `attest()`): no external calls exist in `attest()`; the reentrancy vector does not exist.
- **naming-convention** (Slither): underscore-prefix parameter style is consistent across all 5 contracts; renaming would be a breaking ABI change for zero security benefit.

Slither's final output after all fixes: `naming-convention` detector only (pre-existing style convention, not a security finding). All other detectors clean.

The Hardhat suite grew from 97 tests (pre-audit baseline) to **147 tests** across 7 contract suites, 0 failing.

---

## 5. Why GuardianAI vs. Native Provider Guardrails

A critical question from enterprise buyers: *"OpenAI has moderation APIs and Anthropic has Constitutional AI. Why do I need GuardianAI?"*

The answer is the **AI Shared Responsibility Model**. Model providers secure the *Model Layer* (resisting harmful content at training time). Enterprises are entirely responsible for the *Application Layer*. Native guardrails fall short in five specific scenarios:

| Scenario | Native Guardrails | GuardianAI |
|---|---|---|
| **Data Sovereignty** | PII is transmitted to the provider's servers before any check runs | PII is redacted *before* leaving your network perimeter |
| **API Cost Protection** | Provider charges for tokens processed, even if the output is blocked | Malicious requests are dropped at the proxy — $0 in upstream API cost for attacks |
| **Agentic Tool Execution** | Provider cannot police what happens *after* a tool-call JSON is generated | Tool-Call Policy Engine enforces allow/deny before any local execution |
| **Multi-Model Governance** | Each provider has its own guardrail system — no unified policy | Single, provider-agnostic security plane governs OpenAI, Anthropic, local vLLM, and others uniformly |
| **Web3 Blindspot** | Providers do not write cryptographic proofs to blockchains | CortexAnchor, PassportSBT, and RiskAttestation provide on-chain verifiable AI posture |

---

## 6. Validated Performance

All metrics are sourced from actual test runs and are reproducible.

| Metric | Result |
|---|---|
| Full test suite (Python / pytest, July 2026) | 1,064/1,064 passing, 2 skipped, 0 failed |
| E2E backend-to-blockchain flows | 46/46 passing |
| Smart contract unit tests (Hardhat, August 2026) | 147/147 passing, 0 failed |
| Zero-day attack block rate (unseen datasets) | 98.4% (WildGuard, ToxicChat, JailbreakBench) |
| Standard benchmark block rate | 100% (strict curated subsets) |
| False positive rate | 0.0% |
| HarmBench alignment | 97.0% |
| AdvBench alignment | 94.0% |
| GAIA alignment | 86.0% |
| Composite benchmark | 93.6% |
| Throughput (safe load, concurrency 20) | 67.78 rps |
| Block throughput (attack load, concurrency 20) | 223.20 rps, 100% block rate |
| Attack latency p95 | 96.44 ms |
| SAST findings | 1 flagged, confirmed false positive (documented)\* |
| IaC findings | 0 |
| Internal security audit — critical/high findings (July 2026, off-chain proxy) | 4 identified and remediated\*\* |
| On-chain contract audit — HIGH findings (August 2026) | 1 identified and remediated\*\*\* |
| On-chain contract audit — MEDIUM findings (August 2026) | 4 identified and remediated\*\*\* |

\* SAST flagged a call to `secrets.token_urlsafe()` as a potential hardcoded secret; confirmed as a false positive — the call generates random tokens, not a hardcoded value.

\*\* See Section 6.1 for a summary of the July 2026 internal security audit of the off-chain proxy layer. Prior to this audit, this table did not reflect open findings that existed in the product at the time; the corrected figure is presented here as part of this update.

\*\*\* See the on-chain audit note in Phase 7 (Features 33–38) for per-contract finding breakdown and commit references.

### 6.1 July 2026 Internal Security Audit (Off-Chain Proxy)

GuardianAI's off-chain proxy layer underwent a targeted internal security audit in July 2026, combining automated scanning with direct empirical verification against the live system. The audit identified and remediated four critical-severity findings in the request-handling and authentication layers, along with closing all outstanding gaps in the automated scanner's own detection coverage. All findings were verified as resolved through direct testing against the running system — not test results alone — before being marked closed.

This audit covered the off-chain AI Gateway (Layer 1: proxy, guardrails, and financial-logic validation). The on-chain smart contract layer (Layer 2) is covered separately under the August 2026 audit note in Phase 7 (Features 33–38).

GuardianAI maintains this as an ongoing process: findings are tracked to resolution and verified empirically, and this table is updated to reflect the current state rather than a point-in-time snapshot.

---

## 7. What Makes GuardianAI Unique

### In the AI Security Market

Traditional AI security tools are **passive API scanners** — you send them a request, they return a verdict. GuardianAI is an **active, self-healing control plane**. The Red/Purple Brain generates new defensive rules in milliseconds and applies them to live traffic without restart. No other known open platform combines real-time Red/Blue/Purple team orchestration directly inside the request path.

### In the Web3 Market

Web3 desperately needs AI agents. But blockchains cannot safely process natural language inputs, and no existing platform audits the smart contracts that AI agents write. GuardianAI solves both:
1. Secures AI behavior off-chain at millisecond latency.
2. Audits Solidity/Vyper contracts with 52 verified vulnerability rules (all backed by structural AST/CFG analysis and fixture-tested) before deployment.
3. Anchors behavioral proof on-chain for trustless verification.

No other platform integrates an AI behavioral security gateway, a smart contract static analyzer, and an on-chain identity/liability layer into a single deployable system.

---

## 8. Deployment

### Off-Chain Layer

```bash
# Python (Local)
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt
.\.venv312\Scripts\python.exe guardianctl.py one-click --target-url http://127.0.0.1:8080

# Docker
docker-compose up -d
```

### On-Chain Layer (Monad Testnet)

```bash
# Configure .env with GUARDIAN_DEPLOYER_PRIVATE_KEY and MONAD_RPC_URL
npm install --prefix contracts
npm run deploy:all:monad --prefix contracts
```

---

## 9. Conclusion

GuardianAI is the convergence of high-performance AI security and decentralized cryptographic trust. By securing the immediate execution layer with embedding-based heuristics and process monitoring, auditing the smart contracts agents produce, and cementing the historical and identity layers on the blockchain, GuardianAI provides the definitive security architecture for the autonomous AI economy.

*GuardianAI: Trust the Agent. Verify the Proof.*
