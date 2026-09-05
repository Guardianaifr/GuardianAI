# GuardianAI: Bridging AI Security and Web3 Trust

GuardianAI is a dual-layer security control plane for LLM applications and autonomous AI agents. It provides a blistering-fast, **off-chain security engine** for real-time protection, paired with a decentralized, **on-chain Web3 layer** for cryptographically verifiable trust, identity, and insurance.

By sitting between your application and your model endpoint, GuardianAI neutralizes prompt injections, data leaks, and malicious runtime behaviors in milliseconds—while simultaneously anchoring its security posture to the blockchain (Monad).

---

## 🚀 Dual-Layer Architecture

### 1. The Off-Chain Security Layer (Millisecond Protection)
*What stays off-chain is too fast, too dynamic, or contains PII.*
- **Advanced De-obfuscation:** Decodes extreme Morse variants, Base64, Hex, Braille Steganography, ROT13, Pig Latin, and Homoglyphs.
- **Semantic Firewall:** 18+ Persona/Roleplay heuristics to detect intent-level jailbreaks.
- **Output Protection:** PII redaction (EU AI Act compliance), data leakage prevention, and insecure payload blocking (XSS/SQL).
- **Runtime Monitoring:** Process/resource monitoring, reverse-shell detection, and token-bucket rate limiting.
- **Dynamic Brain Layer:** Red/Blue/Purple/CyberOps agents for real-time automated probing, hotfix generation, and adaptive session hardening.

### 2. The On-Chain Web3 Layer (Cryptographic Trust & Execution Containment)
*What goes on-chain is cryptographic proof, identity, risk scores, and execution-layer containment.*
- **GuardianPolicyGuard (Monad Native):** Hard cryptographic execution gateway enforcing EIP-712 safety attestations, unordered namespaced nonces for conflict-free parallel execution up to 10,000 TPS, and 10 on-chain invariants.
- **Function Selector Allowlists (RBAC) & Outflow Caps:** Zero-trust selector restriction (`AgentPolicy.allowed_selectors`), per-transaction value limits (`max_value_per_tx`), and 24-hour rolling cumulative outflow budgets (`OutflowTracker`) that prevent treasury drains even if an agent's LLM reasoning is fully hijacked.
- **GuardianCortexAnchor:** Periodically publishes Merkle roots of the AI's internal security logs to provide an immutable, timestamped record of its decisions.
- **GuardianPassportSBT:** Issues non-transferable Soulbound Tokens (ERC-5192) representing the verifiable identity and trust score of an AI Agent, with permanent revocation tombstones.
- **GuardianInterlockRegistry:** A decentralized registry for AI agents to request, approve, and verify communication permissions dynamically.
- **GuardianInsuranceLedger:** On-chain insurance certificate anchoring for autonomous agent verification and auditability.
- **GuardianThreatFeedRegistry:** A decentralized, censorship-resistant threat intelligence repository for sharing zero-day patterns.
- **GuardianRiskAttestation:** Enables third parties to verify an agent's real-time risk level before executing Web3 transactions.
- **Identity Gate & Point-of-Interaction Enforcement (ERC-8004 Integration):** Pre-flight identity enforcement for RPC relay transactions and inter-agent communication, featuring on-chain `ownerOf()` verification, structural hot-wallet collision prevention, and zero-downtime shadow observation mode.

---

## 🛠️ Quick Start

### Option A: Docker Compose (Recommended for Evaluators)

```bash
cp .env.example .env          # fill in required values
docker compose up -d
docker compose ps              # verify all services healthy
```

This starts the security proxy (port 8081), dashboard API (port 8001), Redis, and the marketing frontend (port 3000). Point `TARGET_URL` in `.env` at your upstream LLM.

### Option B: Local Python Setup (Development)

```bash
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt
.\.venv312\Scripts\python.exe guardianctl.py one-click --target-url http://127.0.0.1:8080
```

*Generates secure credentials, writes a full-feature config, and starts the proxy & backend.*

### Option C: Web3 Deployment (Monad Testnet)

Ensure you have your wallet private key configured in `.env`, then deploy the integrity layer:
```bash
npm install --prefix contracts
npm run deploy:all:monad --prefix contracts
```

### Option D: Cloud Hosting (Railway / Docker)

GuardianAI ships a production `Dockerfile` and `railway.json`:

```bash
docker build -t guardianai .
docker run -p 8001:8001 -p 8081:8081 --env-file .env guardianai
```

Set `GUARDIAN_PROXY_HOST=0.0.0.0`, point `TARGET_URL` at your upstream LLM,
mount a volume for `guardian.db` and `artifacts/`. See `DEPLOYMENT.md` and
`PRODUCTION_LAUNCH_RUNBOOK.md`.

---

## 📊 Validation Snapshot

Numbers below are sourced directly from reproducible test runs and live on-chain Monad Testnet RPC queries:

- **Smart contracts (Hardhat, September 2026):** **183 passing test cases across 11 contract suites in-repo (100% pass rate, 6s runtime)**. Covers `GuardianPolicyGuard`, `GuardianThreatFeedRegistry`, `GuardianPassportSBT`, `GuardianTimelock`, `GuardianCircuitBreaker`, etc.
- **Python Security & Relay Suites (September 2026):** **176 passing test cases (100% pass rate, 0 failures)** across RPC relay, agentic controls, web3 identity, and runtime interceptor.
- **Real-World Exploit Defense Harness:** **5 / 5 exploits neutralized (100%)** (`tools/reproduce_realworld_exploits.py`):
  - Bankrbot ($204k Morse-code injection)
  - Freysa ($47k calldata redefinition & transfer)
  - aixbt ($104k context poisoning)
  - Permit2 ($1.4M infinite allowance phishing)
  - Monad EVM concurrent nonce replay double-spend
- **Hardcore Live Adversarial Suite:** **38 / 38 real-time live network tests passed** (`tools/hardcore_live_adversarial_suite.py`) against live Monad Testnet and QuickNode WebSocket stream.
- **Attestation Latency Benchmark:** **P50 = 2.68 ms**, Mean = 3.00 ms (measured via `tools/benchmark_attestation_latency.py` over 100 iterations), well within Monad's ~400ms block budget.
- **Monad Testnet Deployed Bytecode (Chain ID 10143):**
  - `GuardianPolicyGuard`: [`0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101`](https://testnet.monadvision.com/contracts/full_match/10143/0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101/) (5,197 bytes)
  - `GuardianThreatFeedRegistry`: [`0xF8B20725b7A35d32c903Af9899FDEFa18bbc44F8`](https://testnet.monadvision.com/contracts/full_match/10143/0xF8B20725b7A35d32c903Af9899FDEFa18bbc44F8/) (7,948 bytes)
  - `GuardianPassportSBT`: [`0x65e081101a08F8c1C2df1cB9D008b3f988fF147f`](https://testnet.monadvision.com/contracts/full_match/10143/0x65e081101a08F8c1C2df1cB9D008b3f988fF147f/) (7,873 bytes)
- **Live On-Chain Transaction Receipts:**
  - Tx [`0x2ac9f4ee...`](https://testnet.monadvision.com/tx/0x2ac9f4eea0e9b918bf915f62e9763e9b67c48aa53425eff90c318106fb04d33a): Confirmed on Monad Block **#59,420,050**, Status 1 (Success), 300,000 Gas.
  - Tx `0x65195a04...`: Confirmed on Monad Block **#59,419,967**, Status 1 (Success), 300,000 Gas.
- **Public Interactive Tenderly Traces:** 19 public simulations on Monad Testnet, e.g. [Verified Valid Execution Trace](https://dashboard.tenderly.co/shared/simulation/b45791d7-a479-475a-a4c7-b26f34f9fc8e).
- **Senior Systems & Cryptographic Audit:**
  - Added `nonReentrant` protection to `sweepETH` in `GuardianPolicyGuard.sol`.
  - Added contract code length verification (`target.code.length > 0`) preventing silent fund loss to EOAs.
  - Added permanent revocation tombstone enforcement (`AgentPermanentlyRevoked`) in `GuardianPassportSBT.sol`.
  - Neutralized `is_wrapped` client-side bypass in both Python and TypeScript agent middleware.
  - Implemented zero-trust function selector allowlists (RBAC) and rolling 24-hour spending caps.
  - Hardened ERC-8004 identity gate and RPC relay: enforced RFC 6750 HTTP 401 vs 403 status code semantics, required attestation and EIP-155 replay protection on `eth_sendRawTransaction`, eliminated pre-auth revocation information leakage, and routed on-chain verification through dedicated QuickNode Monad Testnet RPC.

---

## 📖 Documentation

- **[WHITEPAPER.md](WHITEPAPER.md) (Comprehensive architecture and feature breakdown)**
- `COMPLETE_PROJECT_DOCUMENTATION.md`
- `API.md`
- `DEPLOYMENT.md`
- `ROADMAP.md`

## 🔒 Security Notes
- **Do not expose upstream LLM ports directly to the internet.** Expose only the Guardian Proxy.
- Keep `GUARDIAN_DEPLOYER_PRIVATE_KEY` strictly confidential.
- **ERC-8004 registrar key:** when identity registration is enabled, use a dedicated `GUARDIAN_ERC8004_REGISTRAR_KEY` (never reuse the deployer key). Non-English prompts are translated via a third-party service before filtering — see whitepaper Feature 2 disclosure if you have data-sovereignty constraints.
- **Financial Controls (FL_008 — Slippage):** Hard-blocked until a 1inch API key is provisioned in config. Fails closed (rejects the instruction) when unavailable.
- **Financial Controls (FL_005 — Governance):** Hard-blocked pending a session-wallet auth prerequisite. Fails closed.
- **Agentic Security:** `agentic_security` defaults to opt-in (`enabled: false`). Enable explicitly in `config.yaml` for agentic deployments. See `AI_SECURITY_BACKLOG_2026Q1.md` item 14 for context.

## 📄 License
MIT. See `LICENSE`.
