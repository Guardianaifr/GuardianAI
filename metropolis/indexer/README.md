# GuardianAI Envio HyperIndex (Monad Testnet)

Envio HyperIndex indexer for GuardianAI's contracts on **Monad Testnet (chain ID 10143)**. It turns every
agent wallet, GuardianAI-approved payment, Agent ID card, scam-list entry and Chainlink CRE oracle report
into one GraphQL API.

**Live (Envio Cloud development deployment):** https://indexer.dev.hyperindex.xyz/15eb1b4/v1/graphql

Envio Cloud builds the deployment from the `envio` branch. The development URL changes on every redeploy;
a static production URL needs a paid Envio plan. The code on `main` and on `envio` is the same.

```bash
curl -s https://indexer.dev.hyperindex.xyz/15eb1b4/v1/graphql -H 'content-type: application/json' \
  -d '{"query":"{ EnforcementStats { agentWallets guardianApprovedExecutions } PassportRecord(where:{isRevoked:{_eq:false}}) { tokenId tier } }"}'
```

---

## 1. What is indexed

Envio v3 (`envio` ^3.12.1), HyperSync from block `65,970,000` (one day before the core suite was deployed).
No `rpc:` entry, so Envio uses HyperSync for Monad testnet.

| Contract | Address | Events |
| :--- | :--- | :--- |
| `GuardianPolicyGuard` | `0xa0ae…bB7d` | `ActionExecutedWithAttestation`, `AttestationSignerUpdated`, `MaxAllowedRiskScoreUpdated` |
| `GuardianThreatFeedRegistry` | `0x576C…f467` | `AddressAdded`, `AddressRemoved`, `StringAddressAdded`, `StringAddressRemoved` |
| `GuardianPassportSBT` | `0xb2a8…3566` | `ScoreUpdated`, `PassportRevoked`, `Transfer` (mints only; the handler reads `passports(tokenId)` on-chain because issuance emits no event with the agent hash) |
| `GuardianCortexAnchor` | `0x78aF…dBfa` | `RootCommitted` |
| `GuardianRiskAttestation` | `0x7e06…6c87` | `RiskAttested`, `AttestationUpdated` |
| `GuardianAgentWalletFactory` | `0xAb3a…Ef03` | `WalletCreated` (registers each new wallet dynamically) |
| `GuardianAgentWallet` | every wallet from the factory | `Executed`, `OwnerExecuted`, `Paused`, `Unpaused`, `ThreatOracleUpdated` |
| `GuardianThreatOracle` | `0x2614…dA95` | `ThreatReportAccepted`, `AddressFlagUpdated` |

Full addresses are in `config.yaml` and in the repository [README](../../README.md#-verified-monad-testnet-deployments-chain-id-10143).

### Entities (`schema.graphql`)

| Entity | Holds |
| :--- | :--- |
| `AgentAction` | PolicyGuard executions with risk score and nonce |
| `ThreatRecord` | Scam-list entries from the threat feed registry |
| `PassportRecord` | Agent ID cards (SBT): score, tier, revoked flag |
| `CortexCommitment` | Anchored Merkle roots |
| `ContractRiskRecord` | Risk attestations for target contracts |
| `GlobalSecurityStats` | Singleton counters for the original suite |
| `AgentWallet` | Each `GuardianAgentWallet`: agent id, owner, operator, oracle, paused, counters |
| `AgentWalletExecution` | Each wallet call, GuardianAI-approved (`byOwner: false`) or owner override (`byOwner: true`) |
| `ThreatOracleReport` | Each DON report accepted by the oracle |
| `ThreatOracleFlag` | Current flag per address |
| `EnforcementStats` | Singleton counters for wallets, approved executions, owner executions, oracle reports |

Entity ids are `${txHash}-${logIndex}` (or the lowercased address for per-address entities), so re-processing
a block is idempotent.

---

## 2. Project structure

```
metropolis/indexer/
├── abis/                        # Minimal ABIs for the 8 indexed contracts
├── scripts/sync-indexer-abis.js # Regenerates abis/ from the Hardhat build (contracts/artifacts)
├── src/
│   ├── EnvioHandlers.ts         # v3 registration: indexer.onEvent / indexer.contractRegister
│   └── EventHandlers.ts         # Pure state functions (unit-tested without Envio)
├── test/
│   ├── EventHandlers.test.ts             # 7 core tests
│   ├── EventHandlers.adversarial.test.ts # 29 adversarial tests
│   ├── EnforcementHandlers.test.ts       # 12 agent-wallet / oracle tests
│   └── run-tests.js                      # Runs the three suites
├── config.yaml                  # Contracts, events, start block, field selection
├── schema.graphql               # Entities
└── package.json
```

`dist/` holds an old `tsc` build output and is not used by Envio or the tests.

---

## 3. Run it

Requires Node.js 22.23.4+ (the tests run `.ts` files directly with Node's type stripping).

```bash
cd metropolis/indexer
npm install

npm test             # 48 tests: 7 core + 29 adversarial + 12 enforcement
npm run typecheck    # envio codegen + tsc against the generated types
npm run sync-abis    # after changing contracts: rebuild abis/ (run `npx hardhat compile` in contracts/ first)
```

Local HyperIndex (needs Docker for Postgres + Hasura):

```bash
npx envio dev
```

GraphQL is then at `http://localhost:8080/v1/graphql`.

---

## 4. Example queries

Agent wallets and their GuardianAI-approved payments:

```graphql
query AgentWallets {
  AgentWallet(order_by: { createdAt: desc }) {
    id
    agentId
    operator
    executedCount
    ownerExecutedCount
  }
  AgentWalletExecution(limit: 10, order_by: { timestamp: desc }) {
    wallet
    byOwner
    target
    value
    riskScore
    txHash
  }
}
```

Chainlink CRE oracle state:

```graphql
query Oracle {
  ThreatOracleReport(order_by: { asOf: desc }, limit: 5) { asOf feedDigest changes txHash }
  ThreatOracleFlag(where: { flagged: { _eq: true } }) { id updatedAt }
}
```

Agent ID cards:

```graphql
query Passports {
  PassportRecord(order_by: { score: desc }) { tokenId agentHash score tier isRevoked }
}
```

Original-suite counters:

```graphql
query Stats {
  GlobalSecurityStats(where: { id: { _eq: "global" } }) {
    totalActionsExecuted
    activeThreatCount
    totalPassportsTracked
    totalCortexRootsAnchored
  }
  EnforcementStats { agentWallets guardianApprovedExecutions ownerExecutions oracleReports oracleFlaggedCount }
}
```

---

## 5. Verification

Checked against the chain on Oct 12, 2026: 8 wallets + 34 executions = 42/42 matched Monad receipts; passports
(3 active / 8 revoked) match `activePassportCount`; Cortex, scam-list and oracle counters (`reportCount`,
`flaggedCount`, `feedDigest`) match. Details in [metropolis/README.md §4.B](../README.md#b-envio-event-indexer-metropolisindexer-live-oct-12).
