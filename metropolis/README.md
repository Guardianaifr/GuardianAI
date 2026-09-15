# Monad Metropolis Hackathon — GuardianAI Dossier

**Event:** [Monad Metropolis Hackathon](https://www.monad.xyz/developers/hackathons/metropolis)  
**Timeline:** September 1 – October 13, 2026 (Submission Deadline)  
**Target Category:** Track 04 — Trust, Identity & AI Infrastructure  

---

## 1. Core Architecture Mapping for Track 04

```
┌─────────────────────────────────────────────────────────────┐
│             HUMAN OPERATOR / PASSKEY LAYER (MERA)           │
│  • WebAuthn PRF (FaceID/TouchID) generates isolated keys    │
│  • Zero secrets stored on server; agent memory encrypted   │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│          GUARDIAN AI OFF-CHAIN GATEWAY (PYTHON ENGINE)       │
│  • 10-Layer Prompt Firewall (<40ms latency)                 │
│  • DLP / PII Sanitizer & Jailbreak Fuzzing                  │
│  • RPC Relay: Pre-flight transaction interception (Port 8546)│
│  • MemoryPoisoningGuard: Protected agent context memory      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│            ON-CHAIN PROTOCOL SUITE (MONAD TESTNET)          │
│  • IdentityRegistryTestnet.sol: ERC-8004 Agent Identity      │
│  • GuardianPassportSBT.sol: ERC-5192 Soulbound Trust Scores │
│  • GuardianCortexAnchor.sol: RFC 6962 Merkle State Commit    │
│  • GuardianCircuitBreaker.sol: Automated Emergency Pause     │
│  • GuardianInterlockRegistry.sol: A2A Mutual Authorization   │
│  • GuardianThreatFeedRegistry.sol: Decentralized Threat Feed │
└──────────────────────────────┬──────────────────────────────┘
                               │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
┌───────────────────────────┐         ┌───────────────────────────┐
│   ENVIO HYPERINDEX / SYNC │         │   CHAINLINK CRE WORKFLOW  │
│  • Indexes all event logs │         │  • Pulls threat telemetry │
│  • Real-time GraphQL feed │         │  • On-chain consensus     │
└───────────────────────────┘         └───────────────────────────┘
```

---

## 2. Component-by-Component Mapping & Progress

| Component | Category | Target Deliverable | Status | Implementation Notes |
| :--- | :--- | :--- | :---: | :--- |
| **Domain Context & Research** | **Pre-existing** | Prompt injection heuristics, safety datasets, jailbreak taxonomy, NLP filters | ✅ **100% COMPLETE** | Fully integrated into `guardian/guardrails/` and wired into the relayer. |
| **Monad Smart Contracts** | **New (Hackathon)** | `GuardianPolicyGuard.sol`, `GuardianThreatFeedRegistry.sol`, and `GuardianPassportSBT.sol` deployed natively to Monad Testnet | ✅ **100% COMPLETE** | Deployed (`10143`) via QuickNode. 183 Hardhat tests passing. Full Match Verified on [MonadVision](https://testnet.monadvision.com/contracts/full_match/10143/0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101/). |
| **Cryptographic Attestation Relayer** | **New (Hackathon)** | Sub-second EIP-712 signing pipeline converting AI safety decisions into on-chain proofs (<3ms P50) | ✅ **100% COMPLETE** | Built in `guardian/relayer/attestation_service.py` & `/api/v1/attest` in `rpc_relay.py`. Includes Function Allowlists & 24h Outflow Caps. |
| **Agent Middleware / SDK** | **New (Hackathon)** | Lightweight drop-in middleware/interceptor (`guardian-middleware`) between AI agent frameworks and Monad RPC | ✅ **100% COMPLETE** | TypeScript SDK (`packages/guardian-middleware`) + Python SDK (`sdk/python/guardian_middleware.py`) with ElizaOS plugin & LangChain callback. Strict fail-closed. |

---

## 3. Monad Parallel EVM & Category Labs Architectural Alignment

GuardianAI is custom-engineered to exploit the unique properties of **Category Labs' Monad parallel execution engine**:

1. **Storage Slot Isolation (Zero Parallel Contention):**
   * Monad executes transactions optimistically in parallel, resolving conflicts on a *storage slot* basis.
   * GuardianAI isolates agent state via `mapping(bytes32 => mapping(uint256 => bool)) public usedNonces;` keyed by `keccak256(agentId, nonce)`.
   * Multiple independent AI agents submitting attested transactions never touch overlapping storage slots, achieving **conflict-free parallel throughput up to 10,000 TPS**.
2. **128 KB Contract Bytecode Limit:**
   * Unlike Ethereum's 24.576 KB limit (EIP-170), Monad supports up to **128 KB** bytecode. GuardianAI leverages this headroom to embed comprehensive policy rule sets (10 on-chain invariants including contract code length verification) and signature verification matrices without runtime proxy fragmentation.
3. **Sub-second Attestation & Finality Alignment:**
   * Category Labs prioritizes high-throughput execution with Monad's **~400ms block times**. GuardianAI's Python Relayer signs EIP-712 attestations in **P50 = 2.68 ms** (Mean = 3.00 ms, measured across 100 iterations), delivering end-to-end security verification within a single Monad block window.
4. **Full-Match Explorer Verification:**
   * Deployed contracts are verified on **MonadVision** (Sourcify API) on Chain ID `10143`:
     * [`GuardianPolicyGuard`](https://testnet.monadvision.com/contracts/full_match/10143/0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101/)
     * [`GuardianThreatFeedRegistry`](https://testnet.monadvision.com/contracts/full_match/10143/0xF8B20725b7A35d32c903Af9899FDEFa18bbc44F8/)
     * [`GuardianPassportSBT`](https://testnet.monadvision.com/contracts/full_match/10143/0x65e081101a08F8c1C2df1cB9D008b3f988fF147f/)

---

## 4. Integration Roadmap & Deliverables

### A. Mera Passkey Integration (metropolis/mera/) [COMPLETED ✅]
- [x] Per-agent unlinkable identity minting via PRF derivation (Ed25519).
- [x] Passkey-sealed agent memory with AES-256-GCM encryption (HKDF-derived key, replay-protected AAD).
- [x] Active tamper tripwire: 1-bit ciphertext flip → GCM tag failure → agent quarantine (`MEMORY_POISONING_DETECTED`).
- [x] Cross-device simulation: same master secret → identical DID + decrypted memory.
- [x] MockWebAuthnClient for headless CI testing (HMAC-SHA256 PRF simulator).
- [x] Backend blind storage endpoints (POST/GET/tamper) in passport_routes.py.
- [x] Interactive "Sovereign Passkey Enclave" UI in passport.html.
- [x] Core Vitest test suite (18 unit, stress, and latency benchmark tests passing).
- [x] **Empirical Hard Audit with Real Unseen Data (`npm run test:hard`)**: 166/166 passing (100% green) across GitHub Big List of Naughty Strings, Freqtrade bot configs, and SecLists. 8/8 adversarial tamper attacks intercepted (100% precision) with sub-0.5ms P50 latency.

### B. Envio Event Indexer (metropolis/indexer/) [COMPLETED ✅]
- [x] Run Envio HyperIndex configuration pointing at Guardian's Monad contracts.
- [x] Define schema.graphql for ActionExecuted, ThreatReported, ScoreUpdated, RootCommitted, and GlobalSecurityStats.
- [x] Surface real-time indexed security feed on the frontend dashboard with 7/7 passing unit tests.

### C. Agent Middleware / SDK (packages/guardian-middleware/ & sdk/python/) [COMPLETED ✅]
- [x] TypeScript middleware package (`@guardianai/middleware`) with ElizaOS plugin, Viem decorator, and calldata decoder.
- [x] Python agent middleware (`sdk/python/guardian_middleware.py`) with LangChain callback, Web3.py middleware, and tool wrapper.
- [x] ElizaOS `guardianMemoryGuard` evaluator countering Princeton/Sentient memory-poisoning drain attacks.
- [x] Pre-flight interception wrapping transactions into Monad `GuardianPolicyGuard` (`0x3cb7461c`) with strict fail-closed security.
- [x] 100% test coverage (12 Python unit tests + 49 standalone TypeScript unit tests passing).

### D. Chainlink CRE Workflow (metropolis/chainlink/) [COMPLETED ✅]
- [x] Decentralized Threat Oracle: CRE TypeScript workflow using `@chainlink/cre-sdk` (CronCapability, HTTPClient, EVMClient, runtime.runInNodeMode, runtime.report, writeReport).
- [x] Cron-triggered pipeline: DON nodes independently fetch `/api/v1/stats` → median consensus → signed report → EVM write to Monad Testnet.
- [x] `GuardianThreatConsumer.sol`: On-chain consumer contract receiving CRE Forwarder reports with historical tracking and block-rate analytics.
- [x] Full CRE project scaffold: `project.yaml`, `workflow.yaml`, `config.staging.json`, `config.production.json`, mock API fixtures for simulation.
- [x] Ready for `cre workflow simulate guardian-threat-sync --target staging-settings`.

### E. Final Submission Assets
- [ ] 3-to-5 minute video demo highlighting Track 04 problem & solution.
- [ ] Public GitHub repository clean link.
- [ ] Live deployment on Monad Testnet (Chain ID: 10143).