# 🗺️ GuardianAI Roadmap (v2.0 & Beyond)

**Vision:** expand from "LLM Firewall" to "Comprehensive AI Infrastructure Security".

---

## 🚀 v2.0: The "Universal Auth Proxy" (Q3 2026)
**Goal:** Protect the "Eyes" (Vision) and "Memory" (Vector DBs), not just the "Brains" (LLM).

1.  **Generic Auth Proxy Mode:**
    *   **Feature:** A "Pass-through" mode that enforces Bearer Token Authentication on *any* HTTP service.
    *   **Use Case:** Put Guardian in front of **ComfyUI**, **Qdrant**, or **Ollama** Web UIs.
    *   **Result:** Adds a login screen to tools that don't have one.

2.  **SSH Tunnel Manager:**
    *   **Feature:** Built-in UI to manage secure tunnels to remote GPU servers.
    *   **Benefit:** Replaces manual CLI commands for connecting to `localhost:8188`.

---

## 🛡️ v2.1: Advanced Threat Detection (Q4 2026)
**Goal:** Catch sophisticated attackers who bypass basic filters.

3.  **Adversarial Training (AI Firewall):**
    *   **Feature:** Train the semantic analyzer on new, evolving jailbreak datasets monthly.
    *   **Benefit:** Proactive defense against "zero-day" prompt injections.

4.  **Custom NER Models (PII):**
    *   **Feature:** Replace generic Presidio with fine-tuned models for specific industries (Healthcare/Finance).
    *   **Benefit:** Higher precision, fewer false positives (target <0.1% FP).

5.  **Hash-Based Process Blocking:**
    *   **Feature:** Verify process signatures (SHA256) instead of just names.
    *   **Benefit:** Prevents attackers from bypassing the "Rogue Process" filter by renaming `nc.exe` to `notepad.exe`.

---

## 🔐 v2.2: Enterprise Controls (2027)
**Goal:** Support teams and compliance.

6.  **Role-Based Access Control (RBAC):**
    *   **Feature:** granular permissions (e.g., "Read-Only User", "Admin", "Auditor").
    *   **Benefit:** Secure collaboration for larger teams.

7.  **JWT Authentication:**
    *   **Feature:** Replace static API tokens with cryptographic JSON Web Tokens.
    *   **Benefit:** Stateless, verifiable auth with expiration times.

8.  **SIEM Integration:**
    *   **Feature:** Forward logs to Splunk, Datadog, or Elastic.
    *   **Benefit:** Enterprise-grade monitoring and alerting.
