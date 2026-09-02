# GuardianAI: Bridging AI Security and Web3 Trust

GuardianAI is a dual-layer security control plane for LLM applications and autonomous AI agents. It provides a blistering-fast, **off-chain security engine** for real-time protection, paired with a decentralized, **on-chain Web3 layer** for cryptographically verifiable trust, identity, and insurance.

By sitting between your application and your model endpoint, GuardianAI neutralizes prompt injections, data leaks, and malicious runtime behaviors in milliseconds—while simultaneously anchoring its security posture to the blockchain (Monad / Base).

---

## 🚀 Dual-Layer Architecture

### 1. The Off-Chain Security Layer (Millisecond Protection)
*What stays off-chain is too fast, too dynamic, or contains PII.*
- **Advanced De-obfuscation:** Decodes extreme Morse variants, Base64, Hex, Braille Steganography, ROT13, Pig Latin, and Homoglyphs.
- **Semantic Firewall:** 18+ Persona/Roleplay heuristics to detect intent-level jailbreaks.
- **Output Protection:** PII redaction (EU AI Act compliance), data leakage prevention, and insecure payload blocking (XSS/SQL).
- **Runtime Monitoring:** Process/resource monitoring, reverse-shell detection, and token-bucket rate limiting.
- **Dynamic Brain Layer:** Red/Blue/Purple/CyberOps agents for real-time automated probing, hotfix generation, and adaptive session hardening.

### 2. The On-Chain Web3 Layer (Cryptographic Trust)
*What goes on-chain is cryptographic proof, identity, risk scores, and interlock coordination.*
- **GuardianCortexAnchor:** Periodically publishes Merkle roots of the AI's internal security logs to provide an immutable, timestamped record of its decisions.
- **GuardianPassportSBT:** Issues non-transferable Soulbound Tokens representing the verifiable identity of an AI Agent or User Session.
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

Numbers below are sourced from named artifacts or dated test runs — no hand-typed figures.

- **Python test suites (targeted runs, September 2026):** 107 passed across security, audit chain, web3 identity, relay, and security headers suites (`pytest tests/... -v` in 32.29s) · 33/33 passed on rate limiter heavy stress suite (`tools/test_rate_limiter_heavy.py`) · ERC-8004 identity & Gate 63/63 passed · backend+unit suites 172 passed · passport 24/24.
- **Smart contracts (Hardhat, September 2026):** **160 passing test cases across 10 contract suites in-repo (100% pass rate, 5s runtime)**.
- **Senior Systems & Cryptographic Audit (September 2026):** Completed comprehensive architecture remediation:
  - **CVE-2012-2459 Duplicate Leaf Collision Defense:** Merkle tree RFC 6962 domain separation and odd-leaf promotion (`merkle_anchor.py`).
  - **Atomic Distributed Rate Limiting:** Lua-scripted token replenishment eliminating concurrent check-then-act race conditions (`rate_limiter.py`).
  - **Soulbound SBT Revocation Tombstones:** Permanent on-chain revocation mapping (`GuardianPassportSBT.sol`) and fail-closed burned-token enforcement in `IdentityGate`.
  - **Memory Leak Protection:** Automatic 60-second background daemon sweeps (`RateLimiterJanitor`) with 50,000-bucket capacity bounds.
  - **Gateway Smuggling & DoS Defenses:** RFC 9110 hop-by-hop header stripping and 10MB payload size limits in `interceptor.py`.
- **ERC-8004 integration & Identity Gate:** Protected agents register on canonical ERC-8004 registries and are enforced pre-flight across the Web3 RPC relay and agentic control plane with live on-chain `ownerOf` checks, fail-open resilience, and hot-wallet collision guards.
- **Security validation:** Adversarial benchmark results live in whitepaper Section 6, generated from `artifacts/evidence/definitive_benchmark_v4.json`.

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
