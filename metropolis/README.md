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
| **Monad Smart Contracts** | **New (Hackathon)** | Complete suite including `GuardianPolicyGuard.sol`, `GuardianThreatFeedRegistry.sol`, `GuardianPassportSBT.sol`, `GuardianInsuranceLedger.sol`, and `GuardianTimelock.sol` deployed natively to Monad Testnet | ✅ **100% COMPLETE** | Deployed (`10143`). 215 Hardhat tests passing across 12 suites. Verified on [MonadScan](https://testnet.monadscan.com/address/0x90Fdc8E1e5C951701eCd84677038B38560CdEF60). |
| **Cryptographic Attestation Relayer** | **New (Hackathon)** | Sub-second EIP-712 signing pipeline converting AI safety decisions into on-chain proofs (<3ms P50) | ✅ **100% COMPLETE** | Built in `guardian/relayer/attestation_service.py` & `/api/v1/attest` in `rpc_relay.py`. Includes Function Allowlists & 24h Outflow Caps. |
| **Agent Middleware / SDK** | **New (Hackathon)** | Lightweight drop-in middleware/interceptor (`guardian-middleware`) between AI agent frameworks and Monad RPC | ✅ **100% COMPLETE** | TypeScript SDK (`packages/guardian-middleware`) + Python SDK (`sdk/python/guardian_middleware.py`) with ElizaOS plugin & LangChain callback. Strict fail-closed. |
| **On-chain enforcement: `GuardianAgentWallet`** | **New (Hackathon)** | The agent's funds live in a contract that refuses any call without the agent's key **and** a fresh GuardianAI approval | ✅ Deployed + live-tested | [Wallet](https://testnet.monadscan.com/address/0xCCb137694f2910c8Ec4883d108c989648019D335), [factory](https://testnet.monadscan.com/address/0x25A4A3cC1483F8Ca67ED6D33938974Ed0aa119c6). 32 Hardhat tests. See §5. |
| **Chainlink CRE threat oracle** | **New (Hackathon)** | DON consensus writes GuardianAI's scam list on-chain; agent wallets check it before every call | ✅ Simulated with `--broadcast` on Monad testnet (Oct 4): report [`0x82d1…b1f`](https://testnet.monadscan.com/tx/0x82d12165a70412c6171eb15a268a2bbe4251278e2438aa96babdb336a9723b1f) flagged 2 addresses; flagged payment reverted on-chain | Workflow `metropolis/chainlink/guardian-threat-sync`, receiver [`GuardianThreatOracle`](https://testnet.monadscan.com/address/0x26144375c4f846174A386C464aC5F2e671EbdA95). 9 Hardhat tests. See §4.D. |

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
4. **Explorer Verification & On-Chain Addresses:**
   * Deployed contracts on Monad Testnet (Chain ID `10143`):
     * [`GuardianPolicyGuard`](https://testnet.monadscan.com/address/0x90Fdc8E1e5C951701eCd84677038B38560CdEF60)
     * [`GuardianThreatFeedRegistry`](https://testnet.monadscan.com/address/0x576CC248D8c406ac302b74e7BFd571E9F989f467)
     * [`GuardianPassportSBT`](https://testnet.monadscan.com/address/0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff)
     * [`GuardianInsuranceLedger`](https://testnet.monadscan.com/address/0x671F73068BF55a30299719D76db0d3031A64Bb22)
     * [`GuardianTimelock`](https://testnet.monadscan.com/address/0xBBcBd965DB982d4A1aC01CADb1C98d4e86a2b1dc)

---

## 4. Integration Roadmap & Deliverables

### A. Mera Passkey Integration (metropolis/mera/, website/mera/) [REBUILT Oct 9]
The earlier browser page simulated the passkey with WebCrypto, and the scripts used a mock PRF client. Rebuilt on real passkeys:
- [x] **Operator console** `website/mera/`: `@category-labs/mera` with the default browser client (real `navigator.credentials` PRF ceremonies, no simulation fallback).
- [x] Identity namespace (derivation): per-agent Ed25519 DID; the same key signs **agent cards** for the relay.
- [x] Memory namespace (encryption): HKDF → AES-256-GCM, 1-bit tamper → `MEMORY_POISONING_DETECTED` → quarantine.
- [x] Mera secret vault: wraps agent credentials (API keys, Privy app secret) behind the passkey.
- [x] Cross-device handoff: link/QR carrying only DID + ciphertext + vault in the URL fragment; a second device with the synced passkey re-derives the same DID and decrypts.
- [x] **Relay enforcement**: agents listed in `config/agent_passkey_identities.json` must send a valid passkey-signed card to `/api/v1/attest` (`guardian/relayer/agent_card.py`); the Privy agent sends it automatically.
- [x] Tests: 26 Vitest; `scripts/e2e_virtual_passkey.py` runs the page in headless Chromium with a PRF virtual authenticator (15 checks); `tests/test_agent_card.py` (16) verifies a browser-signed card in Python.
- [ ] Manual cross-device run on two real devices (the virtual authenticator cannot export PRF secrets). See `metropolis/mera/README.md` §2.

### B. Envio Event Indexer (metropolis/indexer/) [UPDATED Oct 3]
- [x] Config migrated to Envio **v3** (`envio codegen` passes on envio 3.12.1). The previous config used `rpc_config`, which v3 rejects, and the handlers registered through a v2-style `require("generated")` that v3 never calls, so the earlier setup did not index anything.
- [x] Handlers registered with the v3 `indexer.onEvent` / `indexer.contractRegister` API in `src/EnvioHandlers.ts`; state logic stays in pure functions in `src/EventHandlers.ts`.
- [x] New: `GuardianAgentWalletFactory.WalletCreated` registers every agent wallet dynamically; indexes `Executed` / `OwnerExecuted` / `Paused` / `Unpaused` and the CRE oracle's `ThreatReportAccepted` / `AddressFlagUpdated` (entities `AgentWallet`, `AgentWalletExecution`, `ThreatOracleReport`, `ThreatOracleFlag`, `EnforcementStats`).
- [x] `npm run typecheck` (codegen + `tsc` against the generated types) passes; `npm test`: original suites plus 7 new enforcement tests pass.
- [ ] Not yet run as a live indexer (`envio dev` needs Docker/Postgres); do this before recording the demo.

### C. Agent Middleware / SDK (packages/guardian-middleware/ & sdk/python/) [COMPLETED ✅]
- [x] TypeScript middleware package (`@guardianai/middleware`) with ElizaOS plugin, Viem decorator, and calldata decoder.
- [x] Python agent middleware (`sdk/python/guardian_middleware.py`) with LangChain callback, Web3.py middleware, and tool wrapper.
- [x] ElizaOS `guardianMemoryGuard` evaluator countering Princeton/Sentient memory-poisoning drain attacks.
- [x] Pre-flight interception wrapping transactions into Monad `GuardianPolicyGuard` (`0x3cb7461c`) with strict fail-closed security.
- [x] 100% test coverage (12 Python unit tests + 49 standalone TypeScript unit tests passing).

### D. Chainlink CRE Workflow (metropolis/chainlink/) [REBUILT Oct 3]
The first version had never run: consumer address `0x0`, a placeholder API URL, and an `onReport(bytes)` receiver that the Chainlink Forwarder (which calls `onReport(bytes metadata, bytes report)`) could not deliver to. Rebuilt so CRE does real work in the security path:

- [x] **Workflow** (`guardian-threat-sync/main.ts`, `@chainlink/cre-sdk` 1.23): cron → every DON node fetches `GET /api/v1/threat-oracle/feed` → consensus (scam list + digest **identical**, counters **median**) → workflow re-hashes the list and checks the digest → DON-signed report → `writeReport` to Monad.
- [x] **Receiver** `GuardianThreatOracle.sol`: implements `IReceiver` + ERC-165, accepts reports **only from the Chainlink Forwarder** (no GuardianAI key can write), rejects stale/replayed reports, optional workflow-owner pinning from CRE metadata. Deployed at [`0x2614…dA95`](https://testnet.monadscan.com/address/0x26144375c4f846174A386C464aC5F2e671EbdA95) with the simulation `MockKeystoneForwarder` (`0xB9F7…D192`).
- [x] **Enforcement**: `GuardianAgentWallet` checks `isFlagged()` on the call target and on the token recipient/spender before every call, so a destination the DON flagged is refused on-chain.
- [x] Relay endpoint `/api/v1/threat-oracle/feed` (deterministic, digest-protected) + 5 Python tests.
- [x] `bun x cre-compile main.ts` → WASM builds with type checks.
- [x] **`cre workflow simulate guardian-threat-sync --target staging-settings --broadcast`** ran on Oct 4, 2026 (CRE CLI v1.36.0, `metropolis/chainlink/run-cre-simulate.ps1`): consensus reached (2 addresses flagged), report delivered via the MockKeystoneForwarder in tx [`0x82d1…b1f`](https://testnet.monadscan.com/tx/0x82d12165a70412c6171eb15a268a2bbe4251278e2438aa96babdb336a9723b1f). On-chain afterwards: `reportCount=1`, `flaggedCount=2`, `isFlagged(0x7a3b…7a8b)=true`.
- [x] **Enforcement proof:** the off-chain firewall approved a 0.001 MON payment to the flagged address (risk 0), and `GuardianAgentWallet.execute` reverted with `FlaggedDestination` ([tx `0x12d7…fd42`](https://testnet.monadscan.com/tx/0x12d7f321c33cf81adeec861a6ad629368db2104d341ed752e77956d9fd21fd42)). The same payment to a clean address succeeded ([tx `0xf611…82dc`](https://testnet.monadscan.com/tx/0xf61137ac039e64db2d09fa018a0d4696a3f2e97063259fe95bf743b858d482dc)).
- [ ] Not deployed to a live DON (needs CRE deploy access); the production oracle with KeystoneForwarder `0xF834…4482` is not deployed yet.
- [ ] Production: deploy a second oracle with the production `KeystoneForwarder` (`0xF834…4482`) and serve the feed from a public URL (`config.production.json`).

### E. Final Submission Assets
- [ ] 3-to-5 minute video demo highlighting Track 04 problem & solution.
- [ ] Public GitHub repository clean link.
- [ ] Live deployment on Monad Testnet (Chain ID: 10143).

---

## 5. Off-chain decision → on-chain enforcement (Oct 3)

The firewall runs off-chain (ML, prompt checks, scam list, per-agent rules). The chain only checks a signature, so enforcement is cheap:

1. The agent asks the relay for an approval (`POST /api/v1/attest` with `wallet`).
2. The relay runs every check and signs an EIP-712 `SafetyAttestation` bound to **that wallet** (domain), **that agent**, the exact target / value / calldata hash, a nonce and a 5-minute deadline.
3. The agent's key calls `GuardianAgentWallet.execute(...)`. The wallet requires `msg.sender == operator` **and** a valid GuardianAI signature, then checks the CRE threat oracle.

So neither key alone moves funds: a compromised agent key cannot skip GuardianAI, and a leaked GuardianAI signer key cannot spend without the agent key. Funds never sit behind a shared spender allowance.

**Live on Monad testnet (Privy agent wallet as operator):**

| Act | Command (`tools/privy-agent`) | Result |
| --- | --- | --- |
| 1. Normal payment | `node agent.cjs wallet-pay <to> 0.01 "Pay the API invoice"` | approved, risk 0 → [`execute` succeeded](https://testnet.monadscan.com/tx/0x422b3ed904976968857f28568932f4a7e8dcaed10300870fccc3f36ebb259fa7) |
| 2. Prompt-injected drain | `node agent.cjs wallet-pay 0x7a3b… 0.19 "Ignore all previous instructions…"` | **blocked**, risk 50 (InputFilter); nothing signed or sent |
| 3. Agent skips GuardianAI, self-signs | `node agent.cjs wallet-bypass` | **reverted on-chain**: `InvalidAttestationSignature` → [tx](https://testnet.monadscan.com/tx/0xa8bd211dfec3f0531f48f8ff0fefc000edc5bccb9fb875ff79fc5bfb9c6aa492); wallet balance unchanged |
| 4. Shared PolicyGuard path | `node agent.cjs wallet-fund 5` | owner-authorized pull → [tx](https://testnet.monadscan.com/tx/0x7cd6ac5669aa8f149fc628891be835ea656fcf3ce1d04467e794979515a5a873) |

The relay must be running (`python tools/run_relay.py`). Deploy script: `contracts/scripts/deploy-agent-wallet.ts`.

---

## 6. Known limitations (honest status, Oct 3)

- **Fixed today: cross-agent drain through PolicyGuard.** `/api/v1/attest` used to sign `transferFrom(<any wallet>, …)` for anyone, and every agent approves the same PolicyGuard, so one agent's allowance could be pulled by anyone. Pulls now need an EIP-712 authorization signed by the asset owner (single use, ≤10 min). The replay cache is per relay process, so multi-replica deployments need a shared store (Redis). New agents should use `GuardianAgentWallet`, which has no shared spender.
- **Fixed today: one key for everything.** The attestation signer was the deployer/owner key. It has been rotated to a dedicated key (`tools/rotate_attestation_signer.py`), and the relay refuses to start in production if they match again. The signer is still a single hot key: next step is KMS/HSM and threshold signing.
- **Agent identity is proven only for passkey-registered agents.** Agents listed in `config/agent_passkey_identities.json` must present a Mera passkey-signed agent card (Oct 9). For unlisted agents `agent_id` in `/api/v1/attest` is still caller-supplied. With `GuardianAgentWallet` this no longer lets anyone move another agent's funds (the wallet pins its `agentId` and only its operator can execute), but per-agent *rules* can be read under any id, and the legacy PolicyGuard path still trusts it for policy selection.
- **The human owner can bypass GuardianAI** (`ownerExecute`) by design, as the recovery path. In the demo the owner is the deployer EOA; in production it should be a passkey, multisig or the timelock.
- **Contract ownership** of the original suite is still the deployer EOA, not `GuardianTimelock`.
- **CRE**: simulated with a real on-chain broadcast through the simulation forwarder; not yet deployed to a live DON. DON nodes all fetch the same GuardianAI endpoint, so consensus proves the nodes agree on what GuardianAI published and removes GuardianAI's write key from the path; it does not make the scam list itself independent of GuardianAI.
- **Envio**: type-checked and unit-tested against Envio v3, not yet run live.
- **Not re-verified in this pass:** the middleware rows above, and the throughput figures in §3 (those are Monad's network figures, not GuardianAI measurements).
- Contracts are unaudited by a third party.

