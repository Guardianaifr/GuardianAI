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

### Option D: Docker

```bash
docker-compose up -d
```
*Endpoints: Proxy (`8081`), Backend API (`8001`), Upstream Target (`8080`).*

---

## 📊 Validation Snapshot

- **Test Suite:** `241/241` passing (including all 46/46 E2E checks)
- **Smart Contracts:** Full suite of 6 deployed contracts passing 56/56 validation tests.
- **Security Validation:** Integrated demo/test flows block 100% of adversarial probes in chaos conditions.

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

## 📄 License
MIT. See `LICENSE`.
