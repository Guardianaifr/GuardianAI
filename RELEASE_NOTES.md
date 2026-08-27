# 🚀 GuardianAI v1.0 Release Notes

**"The Security Layer for Autonomous AI Agents"**

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
    *   Flagship one-command demo: `python demo/full_demo.py` — six scenes ending in dual-chain ERC-8004 live registration.
    *   **Simulation Mode:** Reliable PII testing using mock data.
    *   **"Honest Truth" Disclaimers:** Each demo explicitly states what it proves and what it *does not* prove.

9.  **Unified Launcher:**
    *   `python guardianctl.py start`: single entry point for backend + proxy.
    *   **Setup Wizard:** `python guardianctl.py setup` interactive configuration generator.

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
**License:** See [`LICENSE`](LICENSE).
**Maintainer:** GuardianAI Team

---

## 🔒 v1.0.1 (Smart Contract Security Audit Fixes)
Following a comprehensive senior smart contract audit, the following security and architecture fixes have been applied to the GuardianAI Web3 contracts:
- **[M-1] Parameterized Circuit Breaker Chain:** Replaced the hardcoded `"monad"` chain string in `GuardianCircuitBreaker` with an immutable `chainName` parameter to support multi-chain deployments (Base, Ethereum, Monad) securely.
- **[M-2] CEI Pattern Enforced in Vault:** Fixed a Checks-Effects-Interactions (CEI) ordering vulnerability in `GuardianProtectedVault.deposit()` to prevent hook-token reentrancy.
- **[M-3] Bounded Interlock Registry:** Implemented a hard cap (`MAX_INTERLOCKS = 100,000`) on the `GuardianInterlockRegistry` array growth to prevent gas exhaustion.
- **[L-1] Stale Balance Protection:** Added a `_pause()` hook following `emergencyWithdraw()` in the Vault to prevent withdrawal calls against stale balances.
- **[L-2] Threshold Bounds Check:** Added a strict upper-bound validation (`<= 10000`) to `setRiskScoreThreshold`.
- **[I-1] Agent Hash Zero Check:** Implemented a `bytes32(0)` null check for the agent hash in `GuardianCortexAnchor.commitRoot()`.

*All 159 Web3 contract tests pass successfully.*
