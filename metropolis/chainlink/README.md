# GuardianAI × Chainlink CRE — Decentralized Threat Oracle

> **Monad Metropolis Hackathon** | Track 04 — Trust, Identity & AI Infrastructure  
> **Bounty:** Best workflow with CRE ($3,000 USD)

## What This Is

A **Chainlink Runtime Environment (CRE)** workflow that turns GuardianAI into a **decentralized threat oracle** for the Monad blockchain.

Every 30 seconds, a Chainlink Decentralized Oracle Network (DON):

1. **Fetches** real-time threat telemetry from GuardianAI's security engine
2. **Reaches consensus** across independent nodes (Byzantine Fault Tolerant)
3. **Writes** the verified threat digest to `GuardianThreatConsumer.sol` on Monad Testnet

```
┌──────────────────────────────────────────────────────────────────┐
│                    CRE Workflow DAG                               │
│                                                                  │
│  ⏰ CronTrigger        🌐 HTTP Fetch         🤝 Consensus       │
│  (every 30s)    ───▶   GuardianAI     ───▶   DON Nodes    ───▶  │
│                        /api/v1/stats          Verify Data        │
│                                                                  │
│  📝 Report             📤 Write               ⛓️ On-Chain       │
│  Sign + Encode  ───▶   via Forwarder   ───▶   Monad Testnet     │
│                                               (chain 10143)     │
└──────────────────────────────────────────────────────────────────┘
```

## Architecture

| Layer | Component | Role |
|-------|-----------|------|
| **Trigger** | `CronCapability` | Fires every 30s to start the pipeline |
| **Off-chain** | `HTTPClient` → GuardianAI API | Fetches threat stats (blocked, intercepted, passed) |
| **Consensus** | `runInNodeMode` + median aggregation | Each DON node fetches independently; median consensus produces trusted result |
| **Report** | `runtime.report()` | Generates cryptographically signed DON report |
| **On-chain** | `EVMClient.writeReport()` | Submits signed report to consumer contract on Monad |
| **Contract** | `GuardianThreatConsumer.sol` | Stores verified threat reports with historical tracking |

## Bounty Requirement Mapping

| Requirement | ✅ Deliverable |
|---|---|
| Integrate blockchain with external API | Monad Testnet ← GuardianAI `/api/v1/stats` |
| Demonstrate simulation (CRE CLI) or live deployment | `cre workflow simulate` with passing output |
| CRE meaningfully used as orchestration | Full pipeline: Cron → HTTP → Consensus → Report → EVM Write |

## Project Structure

```
metropolis/chainlink/
├── guardian-threat-sync/          # CRE Workflow
│   ├── main.ts                    # Core workflow (~150 lines)
│   ├── package.json               # Dependencies
│   ├── tsconfig.json              # TypeScript config
│   ├── workflow.yaml              # CRE workflow metadata
│   ├── config.staging.json        # Staging parameters
│   ├── config.production.json     # Production parameters
│   └── tests/
│       └── fixtures/
│           └── mock_stats_api.json # Mock API for simulation
├── contracts/
│   └── GuardianThreatConsumer.sol  # On-chain report consumer
├── project.yaml                   # CRE project config (Monad RPC)
├── secrets.yaml                   # Secret references
├── .env.example                   # Environment template
└── .gitignore
```

## Quick Start

### Prerequisites

- [Bun](https://bun.sh) v1.2.21+
- [CRE CLI](https://docs.chain.link/cre/getting-started/cli-installation) installed
- CRE account ([create one](https://app.chain.link/cre/discover))

### Setup

```bash
# 1. Navigate to the chainlink directory
cd metropolis/chainlink

# 2. Copy and fill in your private key
cp .env.example .env
# Edit .env with your Monad Testnet deployer private key

# 3. Install workflow dependencies
cd guardian-threat-sync
bun install

# 4. Authenticate with CRE
cre login
```

### Simulate

```bash
# From the metropolis/chainlink/ directory:
cre workflow simulate guardian-threat-sync --target staging-settings
```

### Expected Simulation Output

```
Workflow compiled
[SIMULATION] Simulator Initialized
[SIMULATION] Running trigger trigger=cron-trigger@1.0.0
[USER LOG] Guardian threat stats verified — blocked: 1247, intercepted: 14872, passed: 13625
[USER LOG] Signed report generated — writing to consumer 0x...
[USER LOG] ✅ Threat report committed to Monad — TX: 0x...

Workflow Simulation Result:
 {
  "blocked": 1247,
  "intercepted": 14872,
  "passed": 13625,
  "threatDigest": "0xa4b3c2d1..."
}

[SIMULATION] Execution finished signal received
```

## Key Contract: GuardianThreatConsumer

The consumer contract stores verified threat reports on-chain:

- **`latestReport`** — Most recent threat telemetry (blocked, intercepted, passed, digest)
- **`reports[id]`** — Historical report lookup
- **`blockRateBps()`** — Real-time block rate in basis points
- **`isActivelyProtecting()`** — Whether threats are being actively blocked

## Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| Chainlink CRE SDK | `@chainlink/cre-sdk ^1.0.0` | Workflow SDK (triggers, HTTP, EVM, consensus) |
| Viem | `^2.21.0` | ABI encoding for on-chain writes |
| TypeScript | `^5.4.0` | Type-safe workflow authoring |
| Bun | `^1.2.21` | Package manager & WASM compilation |
| Solidity | `^0.8.20` | Consumer contract |
| Monad Testnet | Chain ID 10143 | Target blockchain |

## Resources

- [CRE Documentation](https://docs.chain.link/cre)
- [CRE Templates Repository](https://github.com/smartcontractkit/cre-templates/)
- [CRE Bootcamp](https://smartcontractkit.github.io/cre-bootcamp-2026/)
- [Monad Developer Portal](https://developers.monad.xyz/)
