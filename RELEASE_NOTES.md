# 🚀 GuardianAI v1.0 Release Notes

**"The Security Layer for Autonomous AI Agents"**

GuardianAI v1.0 is a production-ready security layer designed to protect LLM applications from Prompt Injection, PII Leaks, and unauthorized access. It operates on the philosophy of **"Protecting the AI from Blabbing, not the Database from Leaking."**

---

## 🛡️ GuardianAI v1.1.0 Enterprise Security & Cryptographic Architecture Hardening (September 2026)

GuardianAI v1.1.0 incorporates comprehensive enterprise-grade remediations from our senior cryptographic and systems adversarial audit:

1. **Merkle Second-Preimage Defense & CVE-2012-2459 Collision Prevention:**
   - Replaced duplicate leaf padding in `guardian/cortex/merkle_anchor.py` with bottom-up odd leaf promotion.
   - Implemented RFC 6962 domain separation (`0x01` internal node hash prefix), preventing second-preimage attacks between leaves and intermediate nodes.
   - Verified across all odd/prime tree sizes (26/26 tests passed in `tests/security/test_merkle_anchor.py`).

2. **Atomic Distributed Rate Limiter Hot Path:**
   - Implemented `_REDIS_RATE_LIMIT_LUA` script executing atomic token bucket refill, partition recovery deductions, and token consumption within a single Redis atomic transaction.
   - Prevents burst concurrency check-then-act race conditions (33/33 tests passed in `tools/test_rate_limiter_heavy.py`).

3. **Smart Contract Soulbound Revocation Tombstones:**
   - Added permanent `mapping(bytes32 => bool) public isAgentRevoked` to `GuardianPassportSBT.sol`.
   - Hardened `IdentityGate` to identify burned/nonexistent ERC-721 token reverts (`ERC721NonexistentToken`) and fail closed, preventing revoked agents from falling through to unregistered passthrough mode (29/29 SBT tests passed; 59/59 Web3 identity tests passed).

4. **Monotonic Memory Leak Remediation & Janitor Daemon:**
   - Bounded in-memory IP buckets with a `max_local_buckets = 50,000` ceiling.
   - Added `RateLimiterJanitor` background daemon thread running 60-second sweeps to prune stale buckets and purge sliding burst-window timestamps.

5. **Gateway Smuggling & Denial of Service Protection:**
   - Configured `MAX_CONTENT_LENGTH = 10 * 1024 * 1024` (10MB) in `GuardianProxy` with JSON 413 error handling.
   - Stripped all RFC 9110 hop-by-hop headers (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, etc.) before forwarding to upstream LLMs.

6. **Differential Privacy & Keystream Deprecation:**
   - Implemented discrete two-sided geometric noise mechanism (`geometric_noise`) and un-truncated continuous noise (`noisy_count_unbiased`) to eliminate upward statistical bias at zero counts.
   - Strictly prohibited and halted on legacy unauthenticated XOR keystream secrets in production mode.

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

---

## 🛡️ v1.1.0 (ERC-8004 Identity Gate & Point-of-Interaction Enforcement)
- **Pre-flight RPC Relay Gate (`rpc_relay.py`):** Intercepts transaction `from` addresses before execution, validating registered agent identity and trust tiers against canonical ERC-8004 registries and local passports.
- **Agentic Channel Enforcement (`agentic_controls.py`):** Enforces identity verification on inter-agent communication channels with configurable minimum trust tier requirements.
- **Active Hot-Wallet Collision Defense:** Database-level partial unique index (`ON agent_passports(owner_pubkey COLLATE NOCASE) WHERE is_active = 1`) and active-first `LEFT JOIN` resolution on `erc8004_registrations` prevent revoked or orphaned identities from hijacking permissions or causing false-positive blocks.
- **Fail-Open Resilience:** Default fail-open posture (`GUARDIAN_IDENTITY_GATE_FAIL_CLOSED=false`) protects agent uptime during RPC or testnet timeouts with fallback to local state.
- **Zero-Disruption Shadow Mode:** Ships in `GUARDIAN_IDENTITY_GATE_MODE=shadow` by default with `audit_identity_drift.py` and cron automation for safe observation and data reconciliation.
- **100% Regression Suite:** Complete 17-test suite in `tests/web3_identity/test_identity_gate.py` covering live fail-open, on-chain `ownerOf` lookups, and multi-identity tie-breaking.

---

## ⚡ v1.2.0 (Monad Metropolis Track 04 Execution Containment & Hardening)
- **GuardianPolicyGuard Native Monad Deployment (`GuardianPolicyGuard.sol`):** Native execution containment contract deployed to Monad Testnet (`0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101`) enforcing 10 on-chain invariants, EIP-712 cryptographic attestation, and conflict-free parallel execution up to 10,000 TPS.
- **Function Selector Allowlists (RBAC) & Outflow Spending Caps:** Implemented zero-trust selector allowlists (`AgentPolicy.allowed_selectors`), per-transaction value limits (`max_value_per_tx`), and rolling 24-hour cumulative spending budgets (`OutflowTracker`) to contain compromised agent blast radius.
- **Middleware Fail-Closed Bypass Neutralization:** Closed client-side bypass (`is_wrapped`) in Python and TypeScript SDKs, raising `GuardianSecurityBlockedError` (risk 100) on any pre-wrapped input.
- **Smart Contract Invariant Hardening:** Added `nonReentrant` to `sweepETH` in `GuardianPolicyGuard.sol`, added contract code length check (`target.code.length > 0`) preventing silent fund loss against EOAs, and enforced `AgentPermanentlyRevoked` tombstone in `GuardianPassportSBT.sol`.
- **183 / 183 Passing Hardhat Tests:** Full contract suite passes cleanly in 6 seconds across 11 test suites.
- **43 / 43 Passing Python Core Tests:** Full attestation, security, SDK middleware, and policy suites green.
- **Live On-Chain Verification:** Live confirmed transactions on Monad Testnet blocks #59,420,050 and #59,419,967; 19 public interactive Tenderly simulation traces; reproducible benchmark measuring **P50 = 2.68 ms** attestation latency.
