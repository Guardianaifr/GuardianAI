# Guardian Threat Sync — CRE Workflow

Decentralized threat oracle workflow for GuardianAI.

## What It Does

This workflow runs as a scheduled job on a Chainlink DON:

1. **Cron trigger** fires every 30 seconds (staging) / 10 minutes (production)
2. Each DON node independently fetches threat stats from GuardianAI's API
3. **Median consensus** aggregates the results into a single trusted report
4. The signed report is written to `GuardianThreatConsumer.sol` on Monad Testnet

## Files

| File | Purpose |
|------|---------|
| `main.ts` | Workflow logic: fetch → consensus → report → write |
| `workflow.yaml` | Maps targets to entry points and configs |
| `config.staging.json` | Staging params (30s schedule, API URL, chain config) |
| `config.production.json` | Production params (10min schedule) |
| `package.json` | Dependencies (@chainlink/cre-sdk, viem) |
| `tsconfig.json` | TypeScript compiler options |

## Running

```bash
# Install dependencies
bun install

# Simulate (from project root: metropolis/chainlink/)
cre workflow simulate guardian-threat-sync --target staging-settings
```
