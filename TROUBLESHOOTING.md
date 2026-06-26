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


