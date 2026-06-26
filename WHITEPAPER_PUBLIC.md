# GuardianAI Whitepaper

**Version:** 3.0 — Public Edition
**Date:** June 2026
**Classification:** Public

> *Disclaimer: Product and company names referenced for illustrative purposes only reflect the general AI market landscape. All benchmark results are from internal reproducible test runs. This document does not constitute legal, financial, or investment advice.*

---

## 1. Executive Summary

As large language models (LLMs) evolve from passive chatbots into autonomous, tool-wielding agents, the cybersecurity landscape has fundamentally shifted. Traditional security controls are insufficient against semantic jailbreaks, indirect prompt injections, and "Denial of Wallet" attacks in real time. Furthermore, as AI agents begin to execute financial transactions and interact across decentralized digital boundaries, a critical trust gap has emerged: **How do we cryptographically prove the integrity, identity, and security posture of an autonomous AI agent?**

**GuardianAI** is a unified, dual-layer security control plane built to solve this problem end-to-end.

- **Layer 1 — Off-Chain AI Gateway:** Executes 38+ real-time security controls in milliseconds. Addresses the OWASP Top 10 for LLM Applications. Protects against prompt injection, PII leakage, malicious runtime behavior, and unsafe multimodal inputs.
- **Layer 2 — On-Chain Web3 Trust:** Six EVM-compatible smart contracts (Monad/Base) provide cryptographically verifiable AI identity, decentralized authorization, automated liability, and a built-in smart contract static analyzer to audit the very contracts AI agents deploy.

GuardianAI is the **first platform** to combine a production-grade AI security gateway, a smart contract static analyzer, and a decentralized on-chain trust layer in a single, deployable system.

---

## 2. The Problem Statement

### 2.1 The AI Security Crisis (2025–2026)

Prompt injection and agentic exploitation are no longer theoretical attack vectors.

- **Prompt injection is the #1 LLM vulnerability** per OWASP Top 10 for LLM Applications (2025, 2026).
- Audits of production AI deployments in 2025 indicated that **73% of systems were vulnerable** to prompt injection.
- Bug bounty reports for AI-related flaws surged by **540%** in 2025, with payouts for AI vulnerabilities growing **339%** year-on-year.
- Attack success rates against unguarded models range from **50–95%** depending on technique sophistication.

**The threat model has evolved across three critical dimensions:**

**1. From Chatbots to Agents:** Attackers no longer just trick models into producing harmful content. They exploit LLM tool-calling to achieve Remote Code Execution (RCE) on the host system. A critical vulnerability disclosed in 2025 (CVSS 9.6) in a widely used AI coding assistant demonstrated prompt-injection-via-tool-call leading to unauthorized local configuration modification and RCE on developer machines.

**2. Indirect Prompt Injection (IDPI):** Attackers embed malicious instructions inside externally retrieved content — web pages, PDFs, database records — which an AI agent reads during a legitimate task. The hidden instructions hijack the agent without the user ever sending a malicious message directly.

**3. Obfuscated Encoding Attacks:** Safety filters operate on plaintext, but LLMs inherently understand and decode Braille Unicode, Morse code, Base64, and other encoding schemes. Attackers exploit this "Universal Decoder" behavior to carry malicious payloads through filters that cannot see the obfuscated content.

### 2.2 The Web3 Trust and Liability Gap

While Web3 offers cryptographic truth, it lacks native infrastructure to securely onboard autonomous AI agents.

- **The Identity Problem:** Traditional identity systems assume a human at a keyboard. Autonomous AI agents require machine-verifiable cryptographic identities that persist across chains and sessions.
- **The Liability Gap:** As AI agents autonomously trigger smart contracts or DeFi transactions, the legal question of attribution remains unsolved. If an agent hallucinates and drains a wallet, existing systems have no decentralized mechanism to prove what the agent knew, enforce accountability, or trigger an automated payout.
- **The Smart Contract Blindspot:** AI agents increasingly write and deploy smart contracts, but no existing platform combines behavioral AI security with on-chain static analysis. An agent protected by an AI gateway can still transact with a reentrancy-vulnerable contract it helped write.

---

## 3. Architecture Overview

GuardianAI operates on a dual-layer architecture designed to mitigate both classes of threat without compromising throughput.

```
 ┌─────────────┐
 │  Client App │
 └──────┬──────┘
        │
 ┌──────▼────────────────────────────────────────┐
 │            Guardian Proxy (AI Gateway)         │
 │                                                │
 │  Input Security Pipeline                       │
 │  ├─ Encoding de-obfuscation                    │
 │  ├─ Embedding-based semantic firewall          │
 │  ├─ Threat-feed & persona matching             │
 │  ├─ RAG indirect injection guard               │
 │  ├─ Multimodal input security                  │
 │  └─ Tool-call policy engine                    │
 │                      │                         │
 │              Upstream LLM API                  │
 │                      │                         │
 │  Output Security Pipeline                      │
 │  ├─ PII redaction                              │
 │  ├─ Insecure payload blocking                  │
 │  ├─ Cryptographic response tagging             │
 │  └─ Hallucination assurance                    │
 └──────────────────────────────────────────────-─┘
        │
 ┌──────▼────────────────────────────────────────┐
 │         Guardian Backend & Brain               │
 │  ├─ Telemetry & analytics                      │
 │  ├─ Red/Blue/Purple adaptive agents            │
 │  └─ Differential privacy engine                │
 └──────────────────────────────────────────────-─┘
        │
 ┌──────▼────────────────────────────────────────┐
 │         Web3 Integrity Layer (Monad)           │
 │  ├─ CortexAnchor      (Merkle root anchoring)  │
 │  ├─ PassportSBT       (ERC-5192 AI identity)   │
 │  ├─ InterlockRegistry (Agent authorization)    │
 │  ├─ InsuranceLedger   (Automated liability)    │
 │  ├─ ThreatFeedRegistry(Decentralized intel)    │
 │  └─ RiskAttestation   (Verifiable trust score) │
 └──────────────────────────────────────────────-─┘
```

**Design Principle — What Stays Off-Chain:**
Any data that is too fast to chain, too dynamic, or contains PII is processed entirely within the enterprise perimeter. User query content is never written to the blockchain.

**Design Principle — What Goes On-Chain:**
Only cryptographic proofs, identity anchors, authorization states, risk scores, and financial stakes are committed on-chain. Zero PII ever crosses the off-chain boundary.

---

## 4. Feature Breakdown

### Phase 1: Input Security

---

**Feature 1 — Pattern-Based Injection Filter**

A high-speed, first-line-of-defense filter drawn from the full JailbreakBench harm taxonomy (10 categories, 100+ pattern clusters) that intercepts known-bad inputs before any ML inference is invoked.

> **Why it matters:** Sheds high-volume, low-sophistication attacks at zero ML inference cost — protecting API budgets and response latency for legitimate users.

---

**Feature 2 — Embedding-Based Semantic Firewall**

Uses a locally running sentence-embedding model to compute semantic similarity between incoming prompts and a curated library of known attack vectors. Three configurable modes balance precision and recall for different risk appetites.

> **Why it matters:** Attackers constantly rephrase known attacks to evade keyword detection. Semantic similarity catches the *intent* of an attack regardless of how it is worded, blocking zero-day phrasing variations that no regex library can anticipate.

---

**Feature 3 — Advanced Multi-Format De-obfuscation**

Detects and normalizes obfuscated payloads across **9 encoding formats** before they reach the semantic firewall, defeating the "Universal Decoder" attack class:

- Morse code (symbol-based and written-out formats)
- Braille Unicode (full Unicode block U+2800–U+28FF)
- Base64
- Hexadecimal (multiple format variants)
- Binary (8-bit groups)
- ROT13 / Caesar cipher variants
- Unicode Homoglyphs (non-Latin characters mapped to Latin equivalents)
- Pig Latin
- Zero-width and steganographic Unicode characters

> **Why it matters:** Research (UTES / NDSS 2025) shows obfuscated inputs systematically bypass both keyword and embedding-based safety filters by changing the *representation* while preserving malicious *intent*. GuardianAI normalizes the payload back to plaintext first, so all downstream filters operate on the true content.

---

**Feature 4 — Threat-Feed Matching & Persona Heuristics**

A continuously updated pattern library sourced from community threat intelligence, combined with 18+ hand-crafted heuristics covering high-risk "roleplay" and "persona" attack categories.

> **Why it matters:** Threat intelligence is only valuable when it acts in real time. Persona heuristics prevent AI models from being socially engineered into adopting safety-bypass identities — a prerequisite for most advanced jailbreak attacks.

---

**Feature 5 — RAG Indirect Prompt Injection Guard**

Inspects externally retrieved content chunks (documents, web pages, database records) before they enter the prompt context. Detects embedded override instructions, embedding dump attempts, and cross-source trust contamination.

> **Why it matters:** Indirect Prompt Injection is the primary threat vector for any RAG-based or web-browsing AI agent. A document a user legitimately retrieves can silently redirect the agent's behavior — without the user or the application ever knowing.

---

**Feature 6 — Multimodal Input Security**

Validates all non-text content submitted alongside prompts — file attachments, images, and documents.

Controls:
- MIME type allowlisting (blocks disallowed attachment categories)
- Malware scan result enforcement (blocks if scan is absent or failed)
- Prompt injection detection within extracted text from attachments
- Data exfiltration intent detection in extracted content
- Source provenance enforcement (tracks extraction origin and timestamp)

> **Why it matters:** Multimodal jailbreaks — where malicious instructions are embedded inside image files or documents — bypass text-only filters entirely. This is an emerging attack class with documented real-world exploitation (NDSS 2025).

---

**Feature 7 — Output PII Detection and Redaction**

Scans all LLM responses for Personally Identifiable Information (SSNs, payment card numbers, phone numbers, email addresses, healthcare identifiers, and more) before delivery to the client.

> **Why it matters:** Model outputs are a primary data leakage vector — both from training data memorization and from prompt contexts contaminated with user data. This is a foundational GDPR data minimization control and directly supports EU AI Act Article 10 data governance obligations for high-risk AI systems.

---

**Feature 8 — Insecure Output Payload Blocking**

Detects and suppresses AI responses containing executable attack payloads (cross-site scripting, SQL injection, shell commands) before they reach downstream systems.

> **Why it matters:** Prompt injection can cause a model to *output* a malicious payload that the receiving application blindly executes. This is the output-side equivalent of Agentic RCE — and a risk that exists even when the input was never directly adversarial.

---

### Phase 2: Runtime & Process Security

---

**Feature 9 — Runtime Process Monitoring**

Establishes a baseline of expected system processes at startup and continuously monitors for deviations — particularly new processes associated with network attack tooling or unexpected interpreter spawning.

> **Why it matters:** If an AI agent's tool-calling privileges are exploited to initiate a reverse shell or unauthorized data exfiltration, the rogue process becomes visible at the host level before it completes. This provides a host-based detection layer that remains effective even when the application layer is fully bypassed.

---

**Feature 10 — Filesystem Sandboxing**

Enforces an allowlist of permitted filesystem paths accessible to the guardian runtime environment.

> **Why it matters:** Applies the Principle of Least Privilege to the AI execution environment, strictly bounding the blast radius of a compromised agent.

---

**Feature 11 & 12 — IP-Based Token Bucket Rate Limiting (Local + Redis-Distributed)**

A token bucket rate limiter operating in two modes:
- **Local mode:** In-memory, suitable for single-instance deployments.
- **Distributed mode:** Redis-backed with automatic local fallback during Redis partition events — suitable for multi-instance SaaS.

Features: configurable burst capacity, per-source banning, real-time pressure metrics, stale session TTL cleanup, and Redis failover with lazy resynchronization.

> **Why it matters:** Request flooding attacks can exhaust upstream LLM API quotas, causing direct financial loss ("Denial of Wallet"). Rate limiting is the primary financial protection control for pay-per-token AI deployments.

---

### Phase 3: Access Control & Governance

---

**Feature 13 — Authenticated API Access**

All proxy ingest and backend reporting endpoints are protected by securely generated, rotatable credentials.

---

**Feature 14 — Governance Gate**

Security policy configuration changes require a multi-party approval workflow. Changes without valid approval tokens are rejected and logged.

> **Why it matters:** Prevents a compromised administrator account from silently disabling security controls — a critical control for SOC 2 Type II compliance.

---

**Feature 15 — Continuous Hardening Validation**

Background checks continuously verify that the AI system has not been subjected to dataset poisoning, context tampering, groundedness failures, or loss-of-agency drift.

---

**Feature 16 — Compliance Evidence Export**

Automatically generates machine-readable compliance bundles documenting the system's security posture, test results, and governance audit trails in a format suitable for regulatory submission.

> **Why it matters:** Eliminates weeks of manual evidence collection ahead of SOC 2, ISO 27001, or EU AI Act audits.

---

**Feature 17 — HMAC Tamper-Evident Log Signing**

Cryptographically signs all audit logs and evidence bundles using HMAC-SHA256, with support for cloud KMS integration.

> **Why it matters:** Proves to auditors and courts that logs have not been altered after the fact — a prerequisite for legal defensibility in any AI incident investigation.

---

### Phase 4: Dynamic Intelligence (The Brain)

---

**Feature 18 — Red-Team Automated Probe Loop**

Continuously fires adversarial probes against the live system using a curated corpus of known attack vectors, automatically detecting regressions in the security posture.

> **Why it matters:** Static defenses decay as attack techniques evolve. Continuous automated red-teaming is the only way to know whether today's guardrails still work against tomorrow's attacks.

---

**Feature 19 — Blue-Team Adaptive Session Hardening**

Tracks per-session risk scores in real time. When a session's risk exceeds configurable thresholds, the Blue Team automatically tightens rate limits, reduces output permissions, or revokes the session.

> **Why it matters:** Applies proportional security friction — no disruption to safe users, maximum friction for suspicious sessions.

---

**Feature 20 — Purple-Team Auto-Patch & Hot Reload**

When the Red Team discovers an attack pattern that bypasses current defenses, the Purple Team generates and deploys a new defensive rule to the live firewall — **without any service restart**.

> **Why it matters:** The mean time to mitigate a novel attack is reduced from hours (manual patch + deployment) to milliseconds (autonomous detection + in-memory patch). Zero downtime is maintained throughout.

---

**Feature 21 — CyberOps Intelligence Scoring & Brain Orchestrator**

Aggregates threat signals across all detection layers into a unified risk score per session and tenant. The Brain Orchestrator coordinates Red, Blue, and Purple team behavior directly within the live request path.

> **Why it matters:** Creates a unified, real-time operational picture — reducing alert fatigue for security teams while enabling automated, proportional response.

---

**Feature 22 — Session Revocation & External IdP Integration**

Instantly terminates compromised sessions. Integrates with enterprise Identity Providers (Okta, Auth0, Azure AD) by parsing JWT claims and enforcing provider-specific revocation contracts.

> **Why it matters:** A compromised session must be terminated across the entire enterprise identity plane simultaneously — not just at the AI proxy. This prevents an attacker from re-entering via a parallel application while the AI proxy blocks them.

---

**Feature 23 — Honeypot & Deception Controls**

Returns plausible but deliberately false responses to sessions exhibiting highly suspicious behavioral patterns.

> **Why it matters:** Deception technology converts an attacker's strength (patience, persistence) into a weakness. While the attacker probes a fake surface, defenders gather intelligence on their methods and origin.

---

**Feature 24 — Tool-Call Policy Engine**

Defines granular allow / deny / confirm rules for every external tool an AI agent can invoke — API calls, database queries, shell commands, file access.

> **Why it matters:** Implements the Principle of Least Privilege for agentic workflows. Even if an agent is fully compromised via indirect prompt injection, it cannot exceed its pre-authorized tool permissions.

---

**Feature 25 — Multi-Tenant Hard Isolation**

Enforces complete data, session, and rate-limit isolation between tenants. Includes per-tenant cost-abuse metering and automatic quarantine on anomalous spend.

---

**Feature 26 — Performance & Chaos Validation**

Continuously validates system behavior under load and simulated infrastructure failure (upstream model unavailable, backend unavailable) with automated SLO pass/fail reporting.

Validated: 67.78 rps throughput (safe load), 223.20 rps block throughput (attack load, 100% block rate), p95 attack latency of 96.44 ms.

---

### Phase 5: Output Assurance & Analytics

---

**Feature 27 — Hallucination-Risk Output Assurance**

Enforces structured response contracts — validates that AI outputs conform to expected schemas, include required citations, or carry minimum confidence annotations.

> **Why it matters:** Unstructured or unsourced AI outputs in finance, healthcare, and legal contexts carry direct liability. Structured output enforcement is a prerequisite for deploying AI in regulated industries.

---

**Feature 28 — Public Benchmark Alignment**

Normalizes internal detection metrics against published adversarial AI benchmarks (HarmBench, AdvBench, GAIA). Enforces minimum score gates in CI/CD pipelines.

Validated scores: HarmBench 97.0%, AdvBench 94.0%, GAIA 86.0%, composite 93.6%.

---

**Feature 29 — Cryptographic Response Tagging**

Appends an HMAC-signed verification field to AI-generated responses, enabling downstream systems or auditors to verify that a response was processed and approved by GuardianAI.

> **Why it matters:** Directly supports EU AI Act Article 50 transparency obligations for AI-generated content, and provides a non-repudiation mechanism for AI output in regulated and legal contexts.

---

**Feature 30 — Differential Privacy Analytics**

Applies calibrated Laplace noise to aggregated telemetry before reporting, with a privacy budget tracker that enforces total epsilon consumption limits across all queries.

Mechanisms implemented: Laplace (pure DP), Gaussian (approximate DP), exponential mechanism, noisy sum/average, and Local DP via Randomized Response (RAPPOR-lite).

> **Why it matters:** GuardianAI aggregates threat intelligence across deployments to improve defenses for all users. Differential privacy guarantees that no individual user's activity can be reverse-engineered from any aggregate report — satisfying GDPR data minimization at the analytics layer.

---

**Feature 31 — Agentic Controls, Memory Guard & Feedback Loop**

A suite of controls governing long-running agentic workflows: policy enforcement for autonomous action sequences, memory poisoning defenses, and per-tenant false-positive sensitivity tuning with a feedback loop for continuous improvement.

---

### Phase 6: Smart Contract Security Analyzer

> **The most differentiated feature in the Web3 market.** AI agents write and deploy smart contracts. GuardianAI audits them.

---

**Feature 32 — Multi-Chain Solidity/Vyper Static Analyzer**

A production-grade static analysis engine for smart contracts. Detects **35+ vulnerability classes** with severity ratings and compliance control mappings to SOC-2 and ISO 27001.

**Supported vulnerability classes (selected):**

| Vulnerability | Severity | Compliance |
|---|---|---|
| Reentrancy | Critical | SOC-2 CC6.8, ISO 27001 A.14.2.5 |
| Integer Overflow/Underflow | High | SOC-2 CC6.1 |
| Access Control Flaws | Critical | SOC-2 CC6.3/CC6.6 |
| Front-Running / MEV Sandwich | High | SOC-2 CC6.1/CC7.2 |
| `tx.origin` Authentication | High | SOC-2 CC6.3 |
| Delegatecall Misuse | Critical | SOC-2 CC6.8/CC7.4 |
| Flash Loan Attack Surface | Critical | SOC-2 CC6.1/CC7.2 |
| Unprotected `initialize()` | Critical | SOC-2 CC6.3/CC6.6 |
| Uncapped Mint Authority | Critical | SOC-2 CC6.1/CC7.2 |
| Oracle Centralization | High | SOC-2 CC6.1/CC7.2 |
| Signature / Bridge Replay | Critical | SOC-2 CC6.8/CC7.2 |
| Governance Attack | Critical | SOC-2 CC6.3/CC7.2 |
| Storage Collision (Proxy) | High | SOC-2 CC6.8 |
| Read-Only Reentrancy | High | SOC-2 CC6.8/CC7.2 |
| Permit Phishing | High | SOC-2 CC6.3 |
| + 20 additional classes | Various | Full SOC-2 / ISO 27001 mappings |

Analysis input: raw Solidity/Vyper source upload, or on-chain contract address + chain ID (fetches verified source via Etherscan-compatible APIs).

Supported chains: Ethereum, Monad, Base, Arbitrum, Optimism, Polygon, BSC, Avalanche, Solana.

Each finding includes: severity, root cause description, step-by-step remediation guidance, and mapped compliance controls.

> **Why it matters:** The security boundary for an AI agent does not end at the prompt. If an agent writes a reentrancy-vulnerable contract and deploys it on behalf of a user, that is an AI security failure — regardless of how well the prompt was guarded. GuardianAI closes the loop between behavioral AI security and on-chain asset security, a gap no other platform currently addresses.

---

### Phase 7: On-Chain Web3 Integrity Layer

Six EVM-compatible smart contracts deployed on Monad/Base provide cryptographic truth about GuardianAI's operational state, enabling trustless verification by any on-chain counterparty.

---

**Feature 33 — GuardianCortexAnchor (Immutable State Anchoring)**

Periodically commits Merkle roots of the AI gateway's internal security logs and configuration state to the blockchain.

> **Why it matters:** Creates an immutable, timestamped, auditable record of every security decision the AI system made. If an agent is compromised or makes a flawed decision, auditors can cryptographically prove the exact state of the system at that moment — and prove that the logs were not altered afterward. This directly solves the "Attribution Problem" in autonomous AI.

---

**Feature 34 — GuardianPassportSBT (On-Chain AI Identity, ERC-5192)**

Issues non-transferable Soulbound Tokens representing the cryptographic identity and trust tier of an AI agent or session.

Identity properties stored on-chain: cryptographic agent identifier, trust tier (UNVERIFIED / SILVER / GOLD / DIAMOND), trust score (0–10,000 scale), issuance timestamp, and revocation flag.

Implements the ERC-5192 Minimal Soulbound NFT standard — tokens are permanently locked to their minting address and cannot be transferred.

> **Why it matters:** API keys can be leaked. On-chain Soulbound identity cannot be stolen or transferred. Smart contracts and DeFi protocols can programmatically verify an agent's trust tier before permitting any interaction, enabling trustless agent-to-contract authorization.

---

**Feature 35 — GuardianInterlockRegistry (Decentralized Agent Authorization)**

A decentralized registry where AI agents establish, approve, and revoke communication permissions with other agents or services.

> **Why it matters:** Enforces separation of read access from execution access at the network layer. If an agent is compromised, its Interlocks can be globally revoked on-chain in a single transaction — instantly and irrevocably halting its ability to interact with any registered counterparty, regardless of what API keys the attacker holds.

---

**Feature 36 — GuardianInsuranceLedger (Automated Liability)**

A smart contract that holds a deployer stake. If an AI agent cryptographically violates a defined SLA — proven via the immutable CortexAnchor log — the contract automatically slashes the stake or triggers a payout to the affected party.

> **Why it matters:** Converts the abstract question of AI liability into a programmable, self-executing financial instrument. No human adjudication, no legal dispute — just mathematically enforced accountability. This is the infrastructure required for autonomous AI agents to participate in commercial and financial ecosystems with real stakes.

---

**Feature 37 — GuardianThreatFeedRegistry (Decentralized Threat Intelligence)**

An on-chain repository where authorized security nodes publish zero-day threat patterns, malicious actor identifiers, and behavioral indicators of compromise.

> **Why it matters:** Eliminates dependence on any single, centralized threat intelligence vendor. A novel attack discovered against one GuardianAI deployment propagates to all deployments through the on-chain feed — creating a censorship-resistant, crowdsourced immune system for the AI ecosystem.

---

**Feature 38 — GuardianRiskAttestation (Verifiable Trust Scoring)**

Allows GuardianAI or trusted third-party auditors to publish cryptographic risk attestations for AI agents — queryable by any on-chain counterparty.

> **Why it matters:** A DeFi protocol or DAO can require an on-chain risk attestation below a defined threshold before allowing an AI agent to execute a trade, cast a governance vote, or trigger a treasury transaction. This enables fully trustless, risk-gated interactions in decentralized environments.

---

## 5. The Shared Responsibility Model: Why Provider-Level Guardrails Are Not Enough

A question every enterprise buyer asks: *"Our AI provider includes safety features in the subscription. Why do we need GuardianAI?"*

The answer is the **AI Shared Responsibility Model** — a principle identical to the cloud security model most enterprises already operate under. AI model providers secure the *model layer* (training-time safety alignment). Enterprises are entirely responsible for the *application layer* — the prompts, the data, the tools, the deployment environment, and the regulatory obligations. Provider-level features address none of these.

| Gap | What Provider Guardrails Do | What GuardianAI Adds |
|---|---|---|
| **Data Sovereignty** | Data is transmitted to provider infrastructure before any safety check runs | PII is detected and redacted *before* data leaves your network — zero third-party data exposure |
| **API Cost Protection** | You are charged for all tokens processed, including those in blocked malicious requests | Attacks are dropped at the proxy layer — $0 in upstream API costs for adversarial traffic |
| **Agentic Tool Execution** | Provider safety operates on the model output (JSON tool call) — not on what happens when that tool runs locally | Tool-Call Policy Engine enforces allow/deny/confirm before any local execution occurs |
| **Multi-Model Governance** | Each provider offers its own guardrail — policies are fragmented across vendors | A single, provider-agnostic security plane enforces identical policies across all models (cloud API, local, open-source) |
| **Web3 Integration** | Providers do not issue on-chain identities or write cryptographic proofs to blockchains | CortexAnchor, PassportSBT, and RiskAttestation provide on-chain verifiable AI posture queryable by smart contracts |
| **Smart Contract Auditing** | Providers have no visibility into the contracts their agents write | The integrated static analyzer audits every contract before deployment — closing the AI-to-on-chain security loop |

---

## 6. Validated Performance

All metrics are sourced from reproducible test runs against the production codebase.

| Metric | Result |
|---|---|
| Full automated test suite | 241 / 241 passing |
| End-to-end backend-to-blockchain flows | 46 / 46 passing |
| Smart contract unit tests | 56 / 56 passing |
| Zero-day attack block rate (WildGuard, ToxicChat, JailbreakBench) | **98.4%** |
| Standard benchmark block rate (strict curated subsets) | **100%** |
| False positive rate | **0.0%** |
| HarmBench alignment | 97.0% |
| AdvBench alignment | 94.0% |
| GAIA alignment | 86.0% |
| Composite benchmark score | **93.6%** |
| Safe-load throughput (concurrency 20) | 67.78 req/s |
| Attack-load block throughput (concurrency 20) | 223.20 req/s, 100% block rate |
| Attack block latency p95 | 96.44 ms |
| SAST security findings | 0 |
| Infrastructure-as-Code security findings | 0 |
| Open critical/high external review findings | 0 |

---

## 7. What Makes GuardianAI Unique

### In the AI Security Market

Existing AI security tools operate as passive, stateless API scanners — you send a request, receive a verdict, and repeat. GuardianAI is a fundamentally different architecture: an **active, self-healing control plane** that continuously probes itself for weaknesses, generates defensive countermeasures autonomously, and deploys them to live traffic — all without any human intervention or system restart.

No known open platform currently combines real-time Red, Blue, and Purple team orchestration directly within the live inference request path.

### In the Web3 Market

The autonomous AI economy requires infrastructure that does not yet exist at scale:

1. AI agents need verifiable on-chain identities that cannot be spoofed or stolen.
2. DeFi protocols need to query an agent's real-time risk score before permitting transactions.
3. Users need automated, mathematically guaranteed liability when an agent causes harm.
4. Developers need to audit the smart contracts their agents write before deployment.

GuardianAI is the first platform to address all four requirements in a single integrated system.

---

## 8. Quick Start

```bash
# Python — One-click full-feature launch
python guardianctl.py one-click --target-url <your-llm-endpoint>

# Docker
docker-compose up -d

# Web3 deployment (Monad Testnet)
# Configure .env with deployer credentials, then:
npm run deploy:all:monad --prefix contracts
```

---

## 9. Conclusion

GuardianAI is the convergence of high-performance AI security and decentralized cryptographic trust. By securing the immediate execution layer with real-time heuristic and semantic defenses, auditing the smart contracts AI agents produce, and cementing the historical and identity layers on the blockchain, GuardianAI provides the definitive security architecture for the autonomous AI economy.

*GuardianAI: Trust the Agent. Verify the Proof.*
