# GuardianAI Troubleshooting Guide

## 1) Presidio runtime compatibility

### Symptom
- If Presidio dependencies are missing, Guardian falls back to regex detection.

### Cause
- Install dependencies inside the project Python 3.12 virtual environment.

### Fix
- Recommended runtime: Python 3.12.
- Ensure `.venv312` is active before running Guardian.

## 2) Proxy health is down

### Check
- `http://127.0.0.1:8081/health`

### Fix
- Ensure Guardian started: `python guardianctl.py start` (or `python guardian/main.py` for the proxy alone).
- Verify port 8081 is free.

## 3) Backend health is down

### Check
- `http://127.0.0.1:8001/health`

### Fix
- Start backend service process.
- Check logs for DB initialization issues.

## 4) Upstream connection errors (502)

### Symptom
- Proxy returns `502 Bad Gateway`.

### Cause
- Upstream target in config is unreachable.

### Fix
- Confirm upstream is running (default `127.0.0.1:8080`).
- Verify `proxy.target_url` in `guardian/config/config.yaml`.

## 5) Too many 429 responses

### Cause
- Rate limit threshold reached.

### Fix
- Tune `rate_limiting.requests_per_minute` in config.
- Validate client retry behavior.

## 6) Requests blocked unexpectedly (403)

### Cause
- Input filter / AI firewall / threat feed / base64 detector flagged request.

### Fix
- Check backend events: `GET /api/v1/events`.
- Adjust security mode (`strict`/`balanced`/`lenient`) in config.
- Re-test with known safe prompts.

## 7) WebSocket events not appearing

### Check
- `ws://127.0.0.1:8001/ws/threats`

### Fix
- Ensure backend is running and client remains connected.
- Trigger a test blocked prompt and verify event ingestion.

## 8) Final sanity commands

```bash
python -m pytest tests -q
python guardianctl.py status
```

Expected tests status: 1,490+ passed (README test table, October 2026).

## 9) Relay, wallet and explorer issues

- **`/api/v1/attest` returns `agent card required`:** the agent is listed in `config/agent_passkey_identities.json`. Send a passkey-signed card (Mera console at `/mera/`) or remove the entry.
- **Relay refuses to start in production:** `GUARDIAN_ATTESTATION_SIGNER_KEY` is missing, or `GUARDIAN_DEPLOYER_PRIVATE_KEY` is set on the relay. See `deploy/relay/README.md`.
- **`GuardianAgentWallet.execute` reverts:**
  - `InvalidAttestationSignature`: the approval was not signed by the signer the wallet trusts, or was requested without `"wallet"` (so it was not bound to this wallet).
  - `FlaggedDestination`: the target, recipient or spender is flagged on `GuardianThreatOracle` (Chainlink CRE scam list).
  - `AttestationExpired` or `NonceAlreadyUsed`: request a fresh approval (approvals last 5 minutes).
  - `NotOperator`: the call was not sent from the wallet's agent key.
  - `PassportRevokedOrInactive`: the agent's ID card is revoked or missing.
- **Console agent replies are slow:** the hosted ElizaOS agent uses free LLM tiers (Groq, then OpenRouter free models), one call at a time; replies can take up to a minute.
- **Explorer shows old Envio data or errors:** the Envio development URL changes on every redeploy; update `ENVIO_GRAPHQL` in `dashboard/src/explorer/siteConfig.js` and rebuild.
