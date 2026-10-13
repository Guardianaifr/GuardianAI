# Public GuardianAI relay

The relay signs GuardianAI's EIP-712 approvals (`POST /api/v1/attest`) and serves the threat feed that the
Chainlink CRE workflow reads.

**Live:** `https://guardian-relay-production.up.railway.app` (Railway service `guardian-relay`).
The explorer and console call this URL directly (`VITE_GUARDIAN_RELAY_URL` in `dashboard/`), allowed by
`GUARDIAN_CORS_ORIGINS`. The Chainlink staging config reads its feed from the same URL.

## What runs

`python -m guardian.web3sec.cloud_relay` serves the same `GuardianRPCRelay` as `tools/run_relay.py`, behind a public guard:

| Route | Public |
|---|---|
| `GET /health` | yes |
| `POST /api/v1/attest` | yes, rate limited (30/min per client, 120/min total) |
| `GET /api/v1/agents/<id>/rules` | yes (read only) |
| `GET /api/v1/threat-oracle/feed` | yes (read by the Chainlink CRE workflow) |
| RPC proxy `/`, `/rules`, `/whitelist`, `/stats`, rule writes | **404** |

It refuses to start without `GUARDIAN_ATTESTATION_SIGNER_KEY`, and refuses to start if `GUARDIAN_DEPLOYER_PRIVATE_KEY` is present.

Check it:

```bash
curl -s https://guardian-relay-production.up.railway.app/health
curl -s https://guardian-relay-production.up.railway.app/api/v1/threat-oracle/feed
curl -s -X POST https://guardian-relay-production.up.railway.app/api/v1/attest -H "content-type: application/json" \
  -d '{"agent_id":"smoke","target":"0x00000000000000000000000000000000000000c1","value":1}'
```

The last call should return `"status": "approved"` with a signature from the attestation signer that
PolicyGuard and the agent-wallet factory trust.

## Deploy to Railway (Windows PowerShell, from the repo root)

```powershell
npm i -g @railway/cli; railway login
# Dashboard: New project -> Empty project -> Create -> Empty service "guardian-relay"
.\deploy\relay\deploy-railway.ps1            # first run: pick project / environment / service, sets variables, deploys
.\deploy\relay\deploy-railway.ps1 -SkipVars  # later: code only
```

The script copies only the relay files (this `Dockerfile`, `requirements.txt`, `guardian/`, `config/`) into
`.railway-relay\` (git-ignored) with its own `railway.json` (Dockerfile build, `/health` health check), so the
repo-root `railway.json` (one-click stack) is not used. It also uploads `config/agent_passkey_identities.json`,
which is not committed. Options: `-CorsOrigins` (default `https://aiguardian.dev,http://localhost:5173`),
`-RpcUrl` (default `https://testnet-rpc.monad.xyz`).

## Settings

| Variable | Default | |
|---|---|---|
| `GUARDIAN_ATTESTATION_SIGNER_KEY` | none | required; must not be the deployer key |
| `GUARDIAN_ENV` | `production` (set in the Dockerfile) | |
| `GUARDIAN_RELAY_ATTEST_PER_MIN` | 30 | per client (first `X-Forwarded-For` entry; forgeable, so best effort) |
| `GUARDIAN_RELAY_ATTEST_GLOBAL_PER_MIN` | 120 | hard cap for the whole service |
| `GUARDIAN_CORS_ORIGINS` | off in code; the Railway script sets `https://aiguardian.dev,http://localhost:5173` | comma separated |

Run a single instance: the relay keeps nonces, daily caps, the pull-authorization replay cache and rate-limit
counters in memory, and these must not be split across instances.

## Rotating the signer key

Set the new key on the service (or in `.env` and rerun `deploy-railway.ps1`), then point the on-chain
contracts at the new signer with `tools/rotate_attestation_signer.py`.

## Alternative: Google Cloud Run

`deploy.ps1` builds the same image for Cloud Run (service `guardian-relay`, project `kadan-kanakku`, `us-central1`,
signer key in Secret Manager as `guardian-attestation-signer`). This was the first setup and is not the live one.

```powershell
.\deploy\relay\deploy.ps1 -Setup     # once: enable APIs, copy the signer key from .env into Secret Manager
.\deploy\relay\deploy.ps1            # build + deploy
```

Serving it as `aiguardian.dev/api/**` also needs a Firebase Hosting rewrite to the Cloud Run service; the
current `firebase.json` has no such rewrite. Use `--min-instances 1 --max-instances 1` for the reason above.
