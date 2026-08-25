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
- **GuardianInsuranceLedger:** An automated SLA liability contract that slashes stakes or pays out affected users if an AI violates safety parameters.
- **GuardianThreatFeedRegistry:** A decentralized, censorship-resistant threat intelligence repository for sharing zero-day patterns.
- **GuardianRiskAttestation:** Enables third parties to verify an agent's real-time risk level before executing Web3 transactions.

---

## 🛠️ Quick Start

### Option A: Local Python Setup

```bash
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt
.\.venv312\Scripts\python.exe guardianctl.py setup
.\.venv312\Scripts\python.exe guardianctl.py start
```

### Option B: One-Click Full SaaS Launch (All Features)

```bash
.\.venv312\Scripts\python.exe guardianctl.py one-click --target-url http://127.0.0.1:8080
```
*Generates secure credentials, writes a full-feature config, and starts the proxy & backend immediately.*

### Option C: Web3 Deployment (Monad Testnet)

Ensure you have your wallet private key configured in `.env`, then deploy the integrity layer:
```bash
npm install --prefix contracts
npm run deploy:all:monad --prefix contracts
```

### Option D: Docker / Cloud Hosting

GuardianAI runs as a hosted service. The repo ships a `Dockerfile`
(Railway builds from it via `railway.json`; any Docker host works):

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

- **Python test suites (2026-08-23):** ERC-8004 identity 42/42 · backend package 136/136 · passport/security 50/50. Full-suite regeneration pending; 3 known order-dependent tests fail only under full-suite ordering and pass individually (see `OPERATIONS.md`).
- **Smart contracts (Hardhat):** 191 test cases across 9 suites in-repo; runner pass/fail count pending CI regeneration.
- **On-chain audit (August 2026):** findings remediated per internal audit record; Slither clean on naming-convention warnings only.
- **ERC-8004 integration (new, August 2026):** protected agents register on the *canonical* Trustless Agents Identity Registry with register-then-transfer ownership handoff, fail-closed safety gates, and a 42-test offline suite. Disabled by default — see `GUARDIAN_ERC8004_ENABLED` in `.env.example`.
- **Security validation:** adversarial benchmark results live in whitepaper Section 6, generated from `artifacts/evidence/definitive_benchmark_v4.json`.

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
