# GuardianAI Full Platform Demo — "The Life of a Protected Agent"

One command walks a single AI agent (`nova-treasury`, 25 ETH treasury) through
its entire lifecycle on the GuardianAI platform. Six scenes, real product code
end to end, no third-party API keys.

## Run

PowerShell:

```powershell
cd <project-root>
.\.venv312\Scripts\python.exe demo\full_demo.py
```

Variants:

```powershell
.\.venv312\Scripts\python.exe demo\full_demo.py --preview   # Scene 6 never touches network/queue
$env:GUARDIAN_FULL_DEMO_VERBOSE = "1"                       # unsilence logs + tracebacks
```

Typical runtime: ~30–60 s offline (preview); live on-chain adds seconds to a
couple of minutes depending on chain confirmations. Warm-up tip for recording:
run it once, then record the second run.

## Scenes

| # | Stage | What is proven |
|---|-------|----------------|
| 1 | PROVISION | SaaS control plane in-process (full ASGI stack): admin JWT, agent API key, telemetry ingest, tamper-evident audit-chain verify, plan catalog |
| 2 | VET | SSRF-guard refusal proof, smart-contract static analysis (multiple findings on a vulnerable vault), 10-vector attack scan of an unprotected bot (grade F), threat-intel screening (bundled offline feed) |
| 3 | SHIELD | Real `runtime.interceptor` proxy: benign traffic passes, injection attack blocked HTTP 403, customer PII `[REDACTED_*]` before leaving the proxy, wallet untouched |
| 4 | TRUST | Passport issued, Ed25519 Verifiable Credential signed + verified (tamper checked), trust score computed |
| 5 | ASSURANCE | Cortex verifiable memory with live tamper-evidence proof, insurance certificate (off-chain signed), 10-day trial |
| 6 | ON-CHAIN | ERC-8004 registration — LIVE Monad Testnet when `.env` carries the registrar key, honest preview otherwise |

Success looks like six `[OK]` rows in the SUMMARY table and `[LIVE] <chain> —
agentId=N` lines with explorer links.

## Honesty notes (what each beat actually is)

- Control plane runs **in-process via ASGI TestClient** — full middleware stack,
  no network sockets.
- Insurance certificates are **off-chain-signed**; on-chain anchoring exists as
  a separate opt-in mode.
- Contract analysis is **rule-based static analysis** (Slither engine runs if
  installed).
- Threat intelligence uses the **bundled offline feed database**.
- On-chain testnet runs use the **labeled stand-in registry**
  (`0xB986…AfcE`); the canonical ERC-8004 registry is mainnet-only today.
- Known bounded backlog bug: a failed mid-flight step can oscillate
  `metadata`/`failed` within one registration attempt until the outer loop cap
  stops it (visible as repeated cycles; contained at `[40/40]`).

## Ports used

8090 (demo upstream agent), 8081 (GuardianAI proxy), 8099 (throwaway vet-target
bot). The script pre-flights all three and exits cleanly with a message if any
is busy — close the stale process and rerun; it never kills anything itself.

## Live-mode `.env` keys (all optional)

```
GUARDIAN_ERC8004_ENABLED=true
GUARDIAN_ERC8004_CHAINS=monad-testnet
GUARDIAN_IDENTITY_GATE_CHAIN=monad-testnet
GUARDIAN_ERC8004_REGISTRAR_KEY=0x…            # testnet burner only
GUARDIAN_ERC8004_IDENTITY_REGISTRY_OVERRIDE=0xB986…AfcE
GUARDIAN_ERC8004_REGISTRY_MONAD_TESTNET=0xB986…AfcE
GUARDIAN_MAX_GAS_PRICE_GWEI_MONAD_TESTNET=1000
# Per-chain nominal spend caps (nominal gasPrice x gasUsed overstates real
# testnet cost; sized generously on purpose)
GUARDIAN_ERC8004_DAILY_BUDGET_WEI_MONAD_TESTNET=10000000000000000000
```

Live registration is idempotent per agent: the registrar recognizes
`nova-treasury` on later runs and reuses its existing identity, so the
agentId (Monad testnet 3) and explorer link are **stable
across takes** — record today or next week, same numbers.

## Exit codes and known variance

- Exit 0 on a completed run (even if a scene printed `[FAIL]` — the SUMMARY
  table is the truth); exit 1 only when a required port is already busy.
- Trust score / insurance risk level can drift slightly between runs: they are
  computed from accumulated `security_events` history for this agent id in the
  shared database, and the risk engine is deliberately conservative before
  anchor/interlock history accrues.
