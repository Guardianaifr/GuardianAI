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
| **Monad Smart Contracts** | **New (Hackathon)** | `GuardianPolicyGuard.sol`, `GuardianThreatFeedRegistry.sol`, and `GuardianPassportSBT.sol` deployed natively to Monad Testnet | 🟡 **90% COMPLETE** | Contracts compiled, audited, and verified (183 tests passing). Pending live testnet broadcast. |
| **Cryptographic Attestation Relayer** | **New (Hackathon)** | Sub-second EIP-712 signing pipeline converting AI safety decisions into on-chain proofs (<40ms) | ✅ **100% COMPLETE** | Built in `guardian/relayer/attestation_service.py` & `/api/v1/attest` in `rpc_relay.py`. 10/10 tests passing. |
| **Agent Middleware / SDK** | **New (Hackathon)** | Lightweight drop-in middleware/interceptor (`guardian-middleware`) between AI agent frameworks and Monad RPC | ⏳ **PLANNED** | Pre-flight calldata decoding + ERC-8004 identity verification. |

---

## 3. Integration Roadmap & Deliverables

### A. Mera Passkey Integration (metropolis/mera/)
- [ ] Connect Mera WebAuthn PRF to encrypt agent context/memory.
- [ ] Demonstrate cross-device decryption using the same passkey on a second device.

### B. Envio Event Indexer (metropolis/indexer/) [COMPLETED ✅]
- [x] Run Envio HyperIndex configuration pointing at Guardian's Monad contracts.
- [x] Define schema.graphql for ActionExecuted, ThreatReported, ScoreUpdated, RootCommitted, and GlobalSecurityStats.
- [x] Surface real-time indexed security feed on the frontend dashboard with 7/7 passing unit tests.

### C. Chainlink CRE Workflow (metropolis/chainlink/)
- [ ] Implement a verifiable TypeScript workflow via @chainlink/cre-sdk.
- [ ] Query Guardian's off-chain /api/v1/stats endpoint and commit verified threat roots to GuardianThreatFeedRegistry.sol.

### D. Final Submission Assets
- [ ] 3-to-5 minute video demo highlighting Track 04 problem & solution.
- [ ] Public GitHub repository clean link.
- [ ] Live deployment on Monad Testnet (Chain ID: 10143).