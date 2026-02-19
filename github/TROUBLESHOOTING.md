# GuardianAI Troubleshooting Guide

## 1) Presidio / Python 3.14 warnings

### Symptom
- Pydantic V1 compatibility warnings on Python 3.14.

### Cause
- `presidio-analyzer` currently depends on components that are less stable on Python 3.14.

### Fix
- Recommended runtime: Python 3.10-3.12.
- If using 3.14, Guardian can continue with regex fallback behavior for some PII paths.

## 2) Proxy health is down

### Check
- `http://127.0.0.1:8081/health`

### Fix
- Ensure Guardian started: `python guardian/main.py` or `python guardianctl.py start`.
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

Expected tests status: `61 passed`.

