# GuardianAI × Chainlink CRE: decentralized threat oracle

> Monad Metropolis Hackathon · Track 04 · Chainlink CRE bounty

GuardianAI's firewall runs off-chain. This workflow moves its **scam list** on-chain without trusting a
GuardianAI hot key: a Chainlink DON fetches the list, reaches consensus, and the DON-signed report is the
only thing that can write to `GuardianThreatOracle` on Monad. Every `GuardianAgentWallet` reads that oracle
before each call, so a destination the DON flagged is refused **by the chain**, even if every off-chain
component were bypassed.

```
cron ─▶ each DON node: GET /api/v1/threat-oracle/feed      (GuardianAI relay)
     ─▶ consensus: entries + digest IDENTICAL, counters MEDIAN
     ─▶ workflow re-hashes the entries, must equal the digest
     ─▶ runtime.report()  (DON-signed, ECDSA / keccak256)
     ─▶ EVMClient.writeReport ─▶ Chainlink Forwarder ─▶ GuardianThreatOracle.onReport(metadata, report)
                                                          │
                     GuardianAgentWallet.execute() ───────┘ isFlagged(target / recipient / spender) → revert
```

| Piece | Where |
| --- | --- |
| Workflow | `guardian-threat-sync/main.ts` (`@chainlink/cre-sdk` 1.23) |
| Receiver contract | `contracts/contracts/GuardianThreatOracle.sol` (9 Hardhat tests) |
| Deployed receiver (simulation forwarder) | [`0x26144375c4f846174A386C464aC5F2e671EbdA95`](https://testnet.monadscan.com/address/0x26144375c4f846174A386C464aC5F2e671EbdA95) on Monad testnet, forwarder `0xB9F79d863261869B234c481D1f9A7af84AeAd192` (MockKeystoneForwarder) |
| Feed endpoint | `GET /api/v1/threat-oracle/feed` in `guardian/web3sec/rpc_relay.py`, list in `config/threat_oracle_feed.json` |
| Enforcement | `GuardianAgentWallet._checkDestinations` (`contracts/contracts/GuardianAgentWallet.sol`) |

Report ABI (workflow and contract must match):
`(uint64 asOf, uint256 blocked, uint256 intercepted, uint256 passed, bytes32 feedDigest, address[] addrs, bool[] flagged)`.
`asOf` is DON time; the oracle rejects any report not newer than the last one, so an old report can never
un-flag an address.

## Run the simulation (writes a real transaction to Monad testnet)

Needs: [CRE CLI](https://docs.chain.link/cre/getting-started/cli-installation) (tested with v1.36.0),
[Bun](https://bun.sh) ≥ 1.2, and a CRE account API key (app.chain.link → Account Settings).

```bash
# 1. secrets for the CLI (never commit this file; .gitignore covers it)
cd metropolis/chainlink
printf 'CRE_API_KEY=%s\nCRE_ETH_PRIVATE_KEY=%s\n' "<your CRE API key>" "<a funded Monad testnet key, no 0x>" > .env

# 2. dependencies + Javy toolchain
cd guardian-threat-sync && bun install && cd ..

# 3. the staging config reads the live relay feed (guardian-relay-production.up.railway.app).
#    To test against a local relay instead, run `python tools/run_relay.py` from the repo root
#    (port 8546) and set feedUrl in guardian-threat-sync/config.staging.json to
#    http://127.0.0.1:8546/api/v1/threat-oracle/feed

# 4. dry run, then broadcast
cre workflow simulate guardian-threat-sync --target staging-settings -e .env
cre workflow simulate guardian-threat-sync --target staging-settings -e .env --broadcast
```

Check the result on-chain:

```bash
cast call 0x26144375c4f846174A386C464aC5F2e671EbdA95 "isFlagged(address)(bool)" 0x7a3b9c1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b --rpc-url https://testnet-rpc.monad.xyz
cast call 0x26144375c4f846174A386C464aC5F2e671EbdA95 "reportCount()(uint64)" --rpc-url https://testnet-rpc.monad.xyz
```

Then `node tools/privy-agent/agent.cjs wallet-pay 0x7a3b9c1d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b 0.01`:
even if the relay approved it, the wallet reverts with `FlaggedDestination`.

## Production

- Deploy a second `GuardianThreatOracle` with the production KeystoneForwarder for Monad testnet
  `0xF8344CFd5c43616a4366C34E3EEE75af79a74482`, then `setExpectedWorkflowOwner(<your workflow owner>)`.
- Point `config.production.json` at the production oracle (its `oracleAddress` is still `0x0`) and at a public feed URL
  (`feedUrl` currently names `aiguardian.dev/api/...`, which has no hosting rewrite today; the live feed is on Railway),
  then deploy with `cre workflow deploy`.

## Honest scope

All DON nodes fetch the same GuardianAI endpoint, so consensus proves the nodes agree on what GuardianAI
published and removes GuardianAI's private key from the write path; it does not make the list's content
independent of GuardianAI. Adding independent sources (other threat feeds) per node is the next step.

`contracts/GuardianThreatConsumer.sol` in this folder is the earlier stats-only consumer and is superseded
by `GuardianThreatOracle`.
