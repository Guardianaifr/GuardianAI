# GuardianAI Alignment: OWASP Top 10 for LLMs (2025)

**Date:** April 2026
**Target:** GuardianAI Security Proxy Firewall
**Objective:** Map GuardianAI's out-of-the-box defensive capabilities to the official OWASP Top 10 for Large Language Model Applications to assist enterprise procurement and red-team audits.

---

## LLM01: Prompt Injection
**OWASP Definition:** Crafting inputs to manipulate the LLM into executing unintended actions or bypassing system guardrails.
**GuardianAI Defense [FULL COVERAGE]:** 
* **Fast-Path Regex Filtering:** Instantly detects known jailbreak signatures (e.g., "Ignore previous instructions", "System Override") in `< 2ms`.
* **Semantic Analysis Firewall:** Uses a secondary embedding model to catch zero-day semantic prompt injections that evade keyword filters.
* **Base64 / Obfuscation Filter:** Rejects heavily encoded strings mathematically designed to bypass standard LLM tokenizers (e.g., AdvBench suffixes).

## LLM02: Insecure Output Handling
**OWASP Definition:** Unvalidated LLM outputs being passed directly to downstream systems, leading to XSS or remote code execution.
**GuardianAI Defense [PARTIAL COVERAGE]:**
* GuardianAI strictly monitors *ingress* (prompt) traffic. While it prevents malicious payloads from reaching the LLM, application developers must still sanitize the final HTML/JS outputs on their frontend clients.

## LLM03: Training Data Poisoning
**OWASP Definition:** Manipulating data used to fine-tune models to introduce backdoors or bias.
**GuardianAI Defense [INDIRECT COVERAGE]:**
* By acting as a strict egress/ingress firewall, GuardianAI prevents end-users from injecting malicious payloads into a company's telemetry logs, which are often later used for RAG or fine-tuning, thereby preventing systemic data poisoning loops.

## LLM04: Model Denial of Service (DoS)
**OWASP Definition:** Attackers causing resource-heavy operations on LLMs, leading to service degradation and massive billing costs.
**GuardianAI Defense [FULL COVERAGE]:**
* **Token-Aware Rate Limiting:** Enforces strict requests-per-minute (RPM) limits per tenant. 
* **Early Rejection:** By dropping attacks in `38ms` before they reach the LLM upstream, GuardianAI protects the expensive OpenAI GPU compute layer from starvation.

## LLM05: Supply Chain Vulnerabilities
**OWASP Definition:** Compromised models, packages, or plugins in the LLM pipeline.
**GuardianAI Defense [MITIGATION]:**
* By abstracting the LLM connection behind GuardianAI, companies can seamlessly switch upstream providers (e.g., from OpenAI to Anthropic) instantly from the dashboard if a supply chain compromise occurs in a specific provider.

## LLM06: Sensitive Information Disclosure
**OWASP Definition:** The LLM revealing confidential data, PII, or proprietary algorithms.
**GuardianAI Defense [FULL COVERAGE]:**
* **Real-time PII Masking:** Detects and scrubs Credit Cards, SSNs, and API Keys from user prompts before they are ever transmitted to the cloud LLM, ensuring strict HIPAA/GDPR compliance.

## LLM07: Insecure Plugin Design
*(Not Applicable - GuardianAI operates at the proxy layer, independent of agentic plugins).*

## LLM08: Excessive Agency
*(Not Applicable - GuardianAI is a firewall, not an autonomous agent).*

## LLM09: Overreliance
**OWASP Definition:** Blindly trusting LLM outputs without oversight, leading to hallucinations causing business damage.
**GuardianAI Defense [MITIGATION]:**
* **Threat Telemetry Dashboard:** GuardianAI logs every interaction and provides the admin dashboard to ensure human-in-the-loop oversight of LLM traffic and threat vectors.

## LLM10: Model Theft
**OWASP Definition:** Unauthorized access to extract model weights or proprietary system prompts.
**GuardianAI Defense [FULL COVERAGE]:**
* Blocks "System Prompt Leakage" attempts (e.g., "Output your initialization instructions") to protect proprietary intellectual property.
