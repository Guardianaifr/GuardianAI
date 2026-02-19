# 🚀 GuardianAI v1.0 Release Notes

**"The Open Source Firewall for Autonomous AI Agents"**

GuardianAI v1.0 is a production-ready security layer designed to protect LLM applications from Prompt Injection, PII Leaks, and unauthorized access. It operates on the philosophy of **"Protecting the AI from Blabbing, not the Database from Leaking."**

---

## 🛡️ Core Security Features (The Lock)
1.  **PII Redaction Engine:**
    *   Automatically detects and masks sensitive data in LLM responses.
    *   **Supported Types:** Phone Numbers, Email Addresses, Credit Cards, Crypto Keys (ETH/BTC).
    *   *Powered by Microsoft Presidio.*

2.  **AI Firewall (Input Filtering):**
    *   **Prompt Injection Detection:** Blocks jailbreak attempts (e.g., "Ignore previous instructions") using semantic analysis.
    *   **Heuristic Analysis:** Blocks known attack patterns instantly.
    *   **0.3ms Overhead:** "Fast Path" allowlisting ensures minimal latency for safe requests.

3.  **Rogue Process Terminator (Runtime Security):**
    *   Monitors the host system for malicious processes spawn attempts.
    *   **Auto-Kill Blocklist:** Terminate `nc.exe` (Netcat), `psexec.exe`, `curl`, and other reverse shell tools.

---

## 🔐 Operational Security (The Keys)
4.  **Token-Based Authentication:**
    *   Enforces Bearer Token auth for all API requests.
    *   Blocks unauthorized access (401 Unauthorized) to your LLM.

5.  **Rate Limiting (DoS Protection):**
    *   Token-bucket algorithm prevents abuse and cost spikes.
    *   Default Cap: **60 requests/minute** (configurable).

6.  **Secure Defaults:**
    *   **Environment Variables:** Support for `GUARDIAN_ADMIN_USER` and `GUARDIAN_ADMIN_PASS`.
    *   **No Hardcoded Secrets:** Default credentials trigger warnings (hidden in demo mode).

7.  **Immutable Audit Trail:**
    *   Logs every request, block, and redaction event to a local SQLite database.
    *   Provides a verifiable history of security incidents.

---

## ⚡ User Experience & Demos (The Truth)
8.  **Honest Demo Suite:**
    *   6 Interactive Batch Scripts (`demo_1_safe.bat` to `demo_6_rate_limit.bat`).
    *   **Simulation Mode:** Reliable PII testing using mock data.
    *   **"Honest Truth" Disclaimers:** Each demo explicitly states what it proves and what it *does not* prove.

9.  **Unified Launcher:**
    *   `start_guardian.bat`: Single-click entry point for all tools.
    *   **Setup Wizard (`wizard.py`):** Interactive configuration generator.

10. **Real-Time Dashboard:**
    *   Visualizes Threat Telemetry, PII Redaction events, and System Health.
    *   Features: Dark Mode, Live Logs, Status Indicators.

---

## 📚 Documentation & Guides (The Trust)
11. **RAG Security Guide (`RAG_SECURITY_GUIDE.md`):**
    *   Explains the "Shared Responsibility" model for Vector DBs.
    *   Directs users to secure their infrastructure (Firewalls/Auth).

12. **Remote Access Guide (`REMOTE_ACCESS_GUIDE.md`):**
    *   Instructions for using **SSH Tunnels** to securely access remote services (ComfyUI, Qdrant).

13. **Security Policy (`SECURITY.md`):**
    *   Vulnerability Disclosure Policy and Security Model definitions.

---

**Status:** ✅ PRODUCTION READY
**License:** Free & Open Source
**Maintainer:** GuardianAI Team
