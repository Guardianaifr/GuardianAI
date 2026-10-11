# Public relay on Cloud Run

`aiguardian.dev/api/**` → Firebase Hosting rewrite → Cloud Run service `guardian-relay` (project `kadan-kanakku`, `us-central1`).
The browser calls the relay on the same origin as the site, so no CORS is needed in production.

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

## Deploy (Windows PowerShell, from the repo root)

Prerequisites: Google Cloud CLI installed and `gcloud auth login` done; billing enabled on `kadan-kanakku`.

```powershell
.\deploy\relay\deploy.ps1 -Setup     # once: enable APIs, copy the signer key from .env into Secret Manager
.\deploy\relay\deploy.ps1            # build + deploy (repeat after relay code changes)
firebase deploy --only hosting       # publishes the /api/** rewrite (the service must exist first)
```

Check it:

```powershell
curl.exe -s https://aiguardian.dev/api/v1/agents/test/rules
curl.exe -s -X POST https://aiguardian.dev/api/v1/attest -H "content-type: application/json" `
  -d '{"agent_id":"smoke","target":"0x00000000000000000000000000000000000000c1","value":1}'
```

The second call should return `"status": "approved"` with a signature from `0x9bA5…2209` (the PolicyGuard / factory signer).

## Settings

| Variable | Default | |
|---|---|---|
| `GUARDIAN_ATTESTATION_SIGNER_KEY` | (secret `guardian-attestation-signer`) | required |
| `GUARDIAN_RELAY_ATTEST_PER_MIN` | 30 | per client (first `X-Forwarded-For` entry; forgeable, so best effort) |
| `GUARDIAN_RELAY_ATTEST_GLOBAL_PER_MIN` | 120 | hard cap for the whole service |
| `GUARDIAN_CORS_ORIGINS` | off | e.g. `-CorsOrigins "http://localhost:5173"` for local explorer dev |

`--min-instances 1 --max-instances 1` is deliberate: no cold starts, and the relay keeps nonces, daily caps and
rate-limit counters in memory, which must not be split across instances.

## Rotating the signer key

Put the new key in `.env`, run `.\deploy\relay\deploy.ps1 -Setup` (adds a secret version), then `.\deploy\relay\deploy.ps1`.
The on-chain contracts must be pointed at the new signer too (`tools/rotate_attestation_signer.py`).

## Alternative: Railway

If Google Cloud billing isn't available, deploy the same image to Railway with the CLI:

```powershell
npm i -g @railway/cli; railway login
# Dashboard: New project -> Empty project -> Create -> Empty service "guardian-relay"
.\deploy\relay\deploy-railway.ps1            # first run: pick project / environment / service, sets variables, deploys
.\deploy\relay\deploy-railway.ps1 -SkipVars  # later: code only
```

It uploads only the relay files from `.railway-relay\` (git-ignored), with its own `railway.json`
(Dockerfile build, `/health` health check), so the repo-root `railway.json` (one-click stack) is not used.
No Firebase rewrite in this setup: the explorer calls the `*.up.railway.app` URL directly, allowed by
`GUARDIAN_CORS_ORIGINS` (default `https://aiguardian.dev,http://localhost:5173`).
