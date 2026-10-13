# Guardian Threat Sync — CRE workflow

Chainlink CRE workflow that writes GuardianAI's scam list on-chain. Overview, deployed addresses and the
simulation run are in [`../README.md`](../README.md).

## What it does

1. A **cron trigger** fires (every 30 seconds in staging, every 10 minutes in production).
2. Every DON node fetches `GET /api/v1/threat-oracle/feed` from the GuardianAI relay on its own.
3. **Consensus:** the scam list and its digest must be **identical** on all nodes; the counters
   (`blocked`, `intercepted`, `passed`) use the **median**.
4. The workflow re-hashes the agreed list and refuses to continue if it does not match the published digest.
5. It encodes the report `(uint64 asOf, uint256 blocked, uint256 intercepted, uint256 passed, bytes32 feedDigest, address[] addrs, bool[] flagged)`,
   the DON signs it, and `writeReport` delivers it through the Chainlink Forwarder to
   `GuardianThreatOracle.onReport` on Monad testnet.

Every `GuardianAgentWallet` checks `GuardianThreatOracle.isFlagged()` before each call, so a flagged
destination is refused on-chain.

## Files

| File | Purpose |
|------|---------|
| `main.ts` | Workflow: fetch → consensus → digest check → report → `writeReport` (`@chainlink/cre-sdk` ^1.23) |
| `workflow.yaml` | Maps `staging-settings` / `production-settings` to entry point and config |
| `config.staging.json` | 30 s schedule, feed from the live Railway relay, oracle `0x2614…dA95` |
| `config.production.json` | 10 min schedule; oracle address is still `0x0` until the production oracle is deployed |
| `tests/fixtures/` | Sample feed responses |
| `package.json` | `@chainlink/cre-sdk`, `viem`; `postinstall` runs `cre-setup` (Javy toolchain) |

## Running

Needs the [CRE CLI](https://docs.chain.link/cre/getting-started/cli-installation) (tested with v1.36.0) and
[Bun](https://bun.sh) ≥ 1.2. Run from `metropolis/chainlink/` with a `.env` holding `CRE_API_KEY` and
`CRE_ETH_PRIVATE_KEY` (see `../README.md`).

```bash
cd guardian-threat-sync && bun install && cd ..

# dry run
cre workflow simulate guardian-threat-sync --target staging-settings -e .env

# writes a real report to Monad testnet through the simulation forwarder
cre workflow simulate guardian-threat-sync --target staging-settings -e .env --broadcast
```

The staging config reads the hosted feed at
`https://guardian-relay-production.up.railway.app/api/v1/threat-oracle/feed`. To use a local relay instead,
run `python tools/run_relay.py` (port 8546) and point `feedUrl` at `http://127.0.0.1:8546/api/v1/threat-oracle/feed`.
