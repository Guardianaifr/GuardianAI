# GuardianAI Envio HyperIndex (Monad Testnet)

High-speed, real-time blockchain event indexer built on **Envio HyperIndex** for **GuardianAI** on **Monad Testnet (Chain ID 10143)**.

Targeting the Metropolis Hackathon **$1,000 "Best Use of Envio"** Sponsor Bounty.

---

## 1. Overview & Architecture

Autonomous AI agents executing high-frequency financial and contract actions on Monad require sub-second event streaming and real-time observability. GuardianAI deploys on-chain policy guards, soulbound passport registries, cortex merkle state anchors, and threat feeds.

**Envio HyperIndex** captures on-chain security events via **HyperSync**, transforming raw logs into a queryable GraphQL schema powering the Metropolis security dashboard and agent visualizer.

```
┌────────────────────────────────────────────────────────┐
│             MONAD TESTNET (CHAIN ID 10143)             │
│                                                        │
│  • GuardianPolicyGuard: ActionExecutedWithAttestation  │
│  • GuardianThreatFeedRegistry: AddressAdded/Removed    │
│  • GuardianPassportSBT: ScoreUpdated, PassportRevoked  │
│  • GuardianCortexAnchor: RootCommitted (6 params)      │
│  • GuardianRiskAttestation: RiskAttested/Updated       │
└───────────────────────────┬────────────────────────────┘
                            │ HyperSync (~2000x faster than RPC)
                            ▼
┌────────────────────────────────────────────────────────┐
│             ENVIO HYPERINDEX ENGINE                    │
│                                                        │
│  • config.yaml (Modern EVM chains schema)              │
│  • schema.graphql (Entities & Global Stats)            │
│  • src/EventHandlers.ts (Transforms & State Mapping)   │
└───────────────────────────┬────────────────────────────┘
                            │ GraphQL Subscriptions (Port 8080)
                            ▼
┌────────────────────────────────────────────────────────┐
│             GUARDIAN METROPOLIS DASHBOARD              │
│  • Live Agent Activity Stream                          │
│  • Real-Time Threat Blocklist                          │
│  • Soulbound Agent Trust Scores                        │
└────────────────────────────────────────────────────────┘
```

---

## 2. Indexed Smart Contracts

| Contract Name | Monad Role | Key Events Indexed |
| :--- | :--- | :--- |
| **`GuardianPolicyGuard`** | EIP-712 AI policy enforcer | `ActionExecutedWithAttestation`, `AttestationSignerUpdated`, `MaxAllowedRiskScoreUpdated` |
| **`GuardianThreatFeedRegistry`** | On-chain threat registry | `AddressAdded`, `AddressRemoved`, `StringAddressAdded`, `StringAddressRemoved` |
| **`GuardianPassportSBT`** | Soulbound agent identity | `ScoreUpdated`, `PassportRevoked` |
| **`GuardianCortexAnchor`** | Merkle audit state anchor | `RootCommitted` (6 parameters) |
| **`GuardianRiskAttestation`** | Target contract rating | `RiskAttested`, `AttestationUpdated` |

---

## 3. Project Structure

```
metropolis/indexer/
├── abis/                           # Extracted ABI definitions
│   ├── GuardianCortexAnchor.json
│   ├── GuardianPassportSBT.json
│   ├── GuardianPolicyGuard.json
│   ├── GuardianRiskAttestation.json
│   └── GuardianThreatFeedRegistry.json
├── scripts/
│   └── sync-indexer-abis.js        # Automated ABI extractor from Hardhat build
├── src/
│   └── EventHandlers.ts            # Envio event handlers & state transformers
├── test/
│   ├── EventHandlers.test.ts       # Standalone 7-suite unit test runner (Docker-free)
│   └── run-tests.js                # Test execution wrapper
├── config.yaml                     # Envio multi-contract configuration
├── schema.graphql                  # Complete GraphQL entities & stats schema
├── package.json                    # Dependencies & automation scripts
└── README.md                       # This file
```

---

## 4. Quick Start & Execution

### A. Run Unit Tests (Docker-Free)
Run the standalone unit test suite testing all entity transformations and state updates:
```bash
node test/run-tests.js
```
Expected output:
```
Summary: 7 / 7 tests passed successfully (100% green).
```

### B. Sync Contract ABIs
To regenerate minimal ABIs directly from Hardhat build artifacts:
```bash
npm run sync-abis
```

### C. Run Envio Dev (with Docker)
To launch the full local HyperIndex environment (PostgreSQL + Hasura GraphQL console):
```bash
pnpm envio codegen
pnpm envio dev
```
The GraphQL endpoint will be available at: `http://localhost:8080/v1/graphql`

---

## 5. Sample GraphQL Queries for Judges

### 1. Live Agent Execution Feed
Retrieve the latest attestation-backed agent transactions with risk scores:
```graphql
query GetRecentAgentActions {
  AgentAction(limit: 10, order_by: { timestamp: desc }) {
    id
    agentId
    target
    riskScore
    nonce
    timestamp
    txHash
  }
}
```

### 2. Active Threat Blocklist
Retrieve all currently active malicious contracts and drainer addresses:
```graphql
query GetActiveThreats {
  ThreatRecord(where: { active: { _eq: true } }) {
    id
    target
    isStringAddress
    reason
    addedBy
    addedAt
  }
}
```

### 3. Agent Reputation & Soulbound Trust Scores
Retrieve agent trust scores and tier classifications (UNVERIFIED, BRONZE, SILVER, GOLD, DIAMOND):
```graphql
query GetAgentPassports {
  PassportRecord(order_by: { score: desc }) {
    id
    tokenId
    agentHash
    score
    tier
    isRevoked
    updatedAt
  }
}
```

### 4. Cortex Merkle State Commitments
Query on-chain anchored Merkle roots:
```graphql
query GetCortexAnchors {
  CortexCommitment(order_by: { timestamp: desc }, limit: 5) {
    id
    merkleRoot
    agentHash
    eventCount
    periodStart
    periodEnd
    commitmentIndex
    committedBy
  }
}
```

### 5. Global Security Metrics
Query network-wide security stats for dashboard KPI counters:
```graphql
query GetGlobalSecurityStats {
  GlobalSecurityStats(where: { id: { _eq: "global" } }) {
    totalActionsExecuted
    totalThreatsRegistered
    activeThreatCount
    totalPassportsTracked
    totalCortexRootsAnchored
    lastUpdated
  }
}
```

---

## 6. Bounty Rubric Alignment ($1,000 Envio Prize)

1. **Complex Multi-Contract Indexing:** Indexes 5 interconnected security and governance contracts across the Guardian ecosystem on Monad Testnet (`10143`).
2. **Deterministic & Reorg-Resistant:** Employs `${txHash}-${logIndex}` deterministic IDs to ensure idempotency across blockchain reorganizations.
3. **Advanced Schema Design:** Provides relational entities and an aggregate singleton (`GlobalSecurityStats`) for sub-millisecond dashboard queries.
4. **CI/CD Ready:** Automated ABI extraction from Hardhat artifacts (`sync-indexer-abis.js`) and a Docker-independent unit test suite.