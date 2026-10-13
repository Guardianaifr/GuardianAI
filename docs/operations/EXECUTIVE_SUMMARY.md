# GuardianAI Executive Summary (1-Page)

Date: October 13, 2026

## Overall status

- **Off-chain firewall and control plane:** feature-complete for staged rollout; self-hosted via Docker / `guardianctl.py`.
- **On-chain layer:** live on **Monad testnet** (chain ID 10143). Not on mainnet; contracts not audited by a third party.
- **Live demo stack:** website, Attack Lab and Console at aiguardian.dev, public relay and hosted ElizaOS agent on Railway, Envio indexer on Envio Cloud.

## What is delivered

AI agents now hold money and read untrusted text. GuardianAI puts two gates between the AI and the money.

### Gate 1: off-chain firewall
- Prompt firewall in front of the LLM: de-obfuscation (Base64, hex, Morse, Braille, homoglyphs, ROT13), semantic/persona jailbreak detection, PII redaction, output validation, rate limiting, audit chain.
- Relay (`/api/v1/attest`): checks every payment request (prompt, scam list, per-agent rules, selector allowlists, outflow caps) and signs an EIP-712 approval for the exact call.
- SaaS control plane: FastAPI backend with JWT/RBAC, telemetry, scans, passports, compliance reports.

### Gate 2: on-chain enforcement (Monad testnet)
- **`GuardianAgentWallet` + factory:** the agent's funds live in a contract that only moves them with the agent's key **and** a fresh GuardianAI approval bound to that wallet. A fully fooled agent, or a leaked relay key alone, cannot move funds.
- **Chainlink CRE threat oracle:** DON consensus writes GuardianAI's scam list to `GuardianThreatOracle`; every agent wallet refuses flagged destinations. Run as a CRE simulation with a real Monad broadcast; live DON pending deploy access.
- **Agent ID cards:** soulbound passports (`GuardianPassportSBT`), self-claimed through `GuardianPassportIssuer`.
- Original suite: `GuardianPolicyGuard`, threat feed registry, risk attestation, Cortex anchor, interlock registry, insurance ledger, timelock, ERC-8004 testnet registry. Twelve contracts deployed.

### Integrations
- **Category Labs Mera:** one operator passkey derives each agent's identity key, encrypts its memory (1-bit tamper refused) and signs the agent card the relay checks.
- **Privy:** the agent key is a policy-locked server wallet: 6/6 forbidden actions refused.
- **Envio:** every wallet, payment, ID card, scam-list entry and oracle report in one GraphQL API (42/42 checked against receipts).
- **ElizaOS:** plugin + hosted agent; the agent decides, GuardianAI approves, the wallet enforces.

## Key results (with sources)

- **Tests (October 2026, README table):** Hardhat 271; Python 1,490+; Mera 26 Vitest + 166 hard-audit assertions; Envio 48; middleware 49 + 15; hosted ElizaOS agent 10; explorer 52.
- **Benchmarks:** security-gate block rate 97.6% strict / 90.7% balanced; grand totals 76.6% / 58.5%; false positives 11.2% balanced / 29.2% strict (`artifacts/evidence/definitive_benchmark_v4.json`, `fp_clean_measure.json`).
- **Performance:** 95.68 req/s safe traffic, p95 41.88 ms under attack (`artifacts/performance/perf_chaos_report.json`); relay EIP-712 signing P50 2.68 ms (`tools/benchmark_attestation_latency.py`).
- **Real-world exploit patterns:** 5/5 neutralized (`tools/reproduce_realworld_exploits.py`).
- **On-chain proofs:** prompt-injected drain blocked off-chain; agent that skips GuardianAI reverted on-chain (`InvalidAttestationSignature`); CRE-flagged destination reverted on-chain (`FlaggedDestination`). Transactions in `metropolis/README.md`.

## Open items

1. Third-party smart-contract audit; move suite ownership from the deployer EOA to `GuardianTimelock`.
2. Relay signer is a single hot key: move to KMS/HSM or threshold signing.
3. CRE: deploy to a live DON with the production Forwarder; add independent feed sources.
4. Envio: static production endpoint (paid plan).
5. Agent identity is only proven for passkey-registered agents; other `agent_id`s are caller-supplied.
6. Publish `guardianai-eliza` (npm) and the Python SDK (PyPI).

Full list: `metropolis/README.md` §6 (known limitations) and `ROADMAP.md`.

## Recommendation

Go for staged rollout of the off-chain firewall; keep the on-chain layer on testnet until the audit and the
signer-key work are done.
