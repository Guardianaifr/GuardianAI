# 🚀 GuardianAI v1.0 Release Notes

**"The Security Layer for Autonomous AI Agents"**

GuardianAI v1.0 is a production-ready security layer designed to protect LLM applications from Prompt Injection, PII Leaks, and unauthorized access. It operates on the philosophy of **"Protecting the AI from Blabbing, not the Database from Leaking."**

## GuardianAI v1.3.1 On-Chain Caps, Allowlist and Redeploy (October 19, 2026)

`GuardianAgentWallet` now enforces a daily native outflow cap, per-token daily caps and an optional target/selector allowlist on-chain (owner-configured). `GuardianPolicyGuard` rejects EOA targets when calldata is present and `GuardianPassportSBT` exposes `revokedTokenOf`. The contracts were redeployed to Monad Testnet (10143); the old contracts are left running and untouched.

| Contract | Old address | New address |
|---|---|---|
| GuardianPassportSBT | `0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff` | `0xb2a8FeF3591efbd385778906207A054af0Ca3566` |
| GuardianPolicyGuard | `0x90Fdc8E1e5C951701eCd84677038B38560CdEF60` | `0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d` |
| GuardianAgentWalletFactory | `0x25A4A3cC1483F8Ca67ED6D33938974Ed0aa119c6` | `0xAb3aE67587D946e63b3cfFb32C9e32d701B8Ef03` |
| GuardianAgentWallet (Privy agent) | `0xCCb137694f2910c8Ec4883d108c989648019D335` | `0x356EfbC397B104F90795E89F0b755aa5AE4967DD` |
| GuardianPassportIssuer | `0x09AAc2dA0A263323585620A55fcCDb89dea960a6` | `0x9c4acFb906EBF32c2C5115F3D84ab6Db809f2Dd1` |

The threat oracle (`0x26144375c4f846174A386C464aC5F2e671EbdA95`) and the other suite contracts are unchanged. The new wallet has a 1 MON native daily cap. Indexer: PolicyGuard and Factory list both generations, the SBT is the new address only. Existing ID cards on the old SBT are not migrated.

---

## 🧱 GuardianAI v1.3.0 On-Chain Enforcement & Live Integrations (October 2026)

Built for the Monad Metropolis hackathon (Track 04). Details, transactions and limitations: `metropolis/README.md`.

1. **Guarded agent wallets (`GuardianAgentWallet`, `GuardianAgentWalletFactory`):** the agent's funds live in a contract that only moves them with the agent's key **and** a GuardianAI EIP-712 approval bound to that wallet. An agent that skips GuardianAI is reverted on-chain (`InvalidAttestationSignature`).
2. **Chainlink CRE threat oracle (`GuardianThreatOracle`):** DON consensus over the relay's `/api/v1/threat-oracle/feed` writes the scam list on-chain; agent wallets refuse flagged destinations (`FlaggedDestination`). Simulated with a real Monad broadcast; live DON pending.
3. **Agent ID cards (`GuardianPassportIssuer`):** wallet owners self-claim one soulbound card; no server key can mint.
4. **Relay hardening:** fixed a cross-agent drain through PolicyGuard (pulls now need an owner-signed EIP-712 authorization), separated the attestation signer from the deployer key (rotated; relay refuses to start if they match), added per-agent rules, on-chain scam-list checks and x402 pay-per-approval (USDC, testnet).
5. **Mera operator passkey:** real-passkey console at `/mera/`; passkey-signed agent cards enforced by the relay for registered agents.
6. **Privy:** the agent key is a policy-locked server wallet (`tools/privy-agent`), 6/6 forbidden actions refused.
7. **Envio:** indexer migrated to HyperIndex v3 and live on Envio Cloud, now covering agent wallets and the oracle (48 tests).
8. **ElizaOS:** ElizaOS 1.7 plugin for the guarded wallet, hosted agent per console wallet (Railway, Groq → OpenRouter free models), `guardianai-eliza` CLI (not yet on npm).
9. **Explorer:** new Attack Lab and Console at `aiguardian.dev/explorer/`; public relay moved to Railway.
10. **Tests:** Hardhat 271, Python 1,490+, Mera 26 + 166, explorer 52, middleware 49 + 15.

---

## 🛡️ GuardianAI v1.2.0 Monad Testnet Hardening & ERC-8004 Identity Assurance (September 2026)

GuardianAI v1.2.0 establishes dedicated on-chain trust and runtime security invariants:

1. **Monad Testnet Dedicated Architecture (Chain ID 10143):**
   - Refocused all smart contract deployments, registrar queues, and RPC relays exclusively on Monad Testnet.
   - Integrated automated SQLite schema and row migration for backwards compatibility with legacy databases.
   - Routed all on-chain identity checks, contract verification, and relay traffic to dedicated QuickNode Monad Testnet RPC endpoints.

2. **RPC Relay Raw Transaction Attestation & EIP-155 Replay Protection:**
   - Mandated attestation verification and sender address recovery for `eth_sendRawTransaction`.
   - Enforced fail-closed EIP-155 replay protection, rejecting transactions lacking explicit Monad chain IDs.
   - Cross-referenced transaction senders with on-chain ERC-8004 registry ownership (`ownerOf`).

3. **RFC 6750 Status Code Semantics (401 vs 403):**
   - Accurately distinguished authentication failures (HTTP 401 with `WWW-Authenticate: Bearer ...`) from authorization blocks (HTTP 403).
   - Eliminated pre-authentication identity probing information leakage by validating attestations prior to querying revocation status.
   - Enabled default on-chain `ownerOf` validation on Monad Testnet.

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
    *   Flagship one-command demo: `python demo/full_demo.py` — six scenes ending in Monad ERC-8004 live registration.
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
11. **RAG Security Guide (`../architecture/RAG_SECURITY_GUIDE.md`):**
    *   Explains the "Shared Responsibility" model for Vector DBs.
    *   Directs users to secure their infrastructure (Firewalls/Auth).

12. **Security Policy (`SECURITY.md`):**
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
- **Zero-Disruption Shadow Mode:** Ships in `GUARDIAN_IDENTITY_GATE_MODE=shadow` by default with `audit_identity_drift.py` and cron automation for safe observation and data reconciliation (the script was later removed, on 2026-09-24).
- **100% Regression Suite:** Complete 17-test suite in `tests/web3_identity/test_identity_gate.py` covering live fail-open, on-chain `ownerOf` lookups, and multi-identity tie-breaking.

---

## ⚡ v1.2.0 (Monad Metropolis Track 04 Execution Containment & Hardening)
- **GuardianPolicyGuard Native Monad Deployment (`GuardianPolicyGuard.sol`):** Native execution containment contract deployed to Monad Testnet (first deployment `0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101`; the current one is `0x90Fdc8E1e5C951701eCd84677038B38560CdEF60`, see README) enforcing 10 on-chain invariants, EIP-712 cryptographic attestation, and conflict-free parallel execution up to 10,000 TPS.
- **Function Selector Allowlists (RBAC) & Outflow Spending Caps:** Implemented zero-trust selector allowlists (`AgentPolicy.allowed_selectors`), per-transaction value limits (`max_value_per_tx`), and rolling 24-hour cumulative spending budgets (`OutflowTracker`) to contain compromised agent blast radius.
- **Middleware Fail-Closed Bypass Neutralization:** Closed client-side bypass (`is_wrapped`) in Python and TypeScript SDKs, raising `GuardianSecurityBlockedError` (risk 100) on any pre-wrapped input.
- **Smart Contract Invariant Hardening:** Added `nonReentrant` to `sweepETH` in `GuardianPolicyGuard.sol`, added contract code length check (`target.code.length > 0`) preventing silent fund loss against EOAs, and enforced `AgentPermanentlyRevoked` tombstone in `GuardianPassportSBT.sol`.
- **183 / 183 Passing Hardhat Tests:** Full contract suite passes cleanly in 6 seconds across 11 test suites.
- **43 / 43 Passing Python Core Tests:** Full attestation, security, SDK middleware, and policy suites green.
- **Live On-Chain Verification:** Live confirmed transactions on Monad Testnet blocks #59,420,050 and #59,419,967; 19 public interactive Tenderly simulation traces; reproducible benchmark measuring **P50 = 2.68 ms** attestation latency.
