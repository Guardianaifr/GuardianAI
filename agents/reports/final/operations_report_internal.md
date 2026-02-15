
# GuardianAI v1.0 Operational Readiness Report (Internal)

**Date:** February 13, 2026
**Audience:** DevOps / SRE / Security Team
**Status:** **READY FOR RELEASE**

---

## 1. Deployment Checklist

### Infrastructure
- [x] **Dockerized:** Application is fully contained. See `docker-compose.yml`.
- [x] **Stateless:** Can be deployed behind any standard Load Balancer (NGINX, ALB).
- [x] **Configurable:** All secrets/settings via Environment Variables.
- [x] **Persistence:** Local SQLite + WAL mode active. Recommendations to mount volume `/app/data`.

### Security Hardening (Phase 3 & 4 Complete)
- [x] **Security Modes:** `Strict`, `Balanced`, `Lenient` configurability active.
- [x] **Base64 Detection:** `Base64Detector` active (blocks hidden payloads).
- [x] **PII Redaction:** Default regex rules active for Emails, IPs, Credit Cards.
- [x] **Rate Limiting:** Token bucket algorithm active per IP.

---

## 2. Monitoring & Observability

### Logs
*   **Format:** JSON structured logs (via backend) or standard stdout.
*   **Levels:** Configurable `LOG_LEVEL` (Default: INFO).
*   **Critical Alerts:** Look for:
    *   `[CRITICAL] Data Leak Prevented`
    *   `[HIGH] Injection Attempt Detected`
    *   `[ERROR] Threat Feed Update Failed`

### Telemetry
*   The proxy sends async telemetry to the `BACKEND_URL`.
*   **Metrics to Watch:**
    1.  **Latency p95:** Alert if >100ms.
    2.  **Error Rate (5xx):** Alert if >1%.
    3.  **Block Rate (403):** Alert if spike >10% (potential false positive storm).

---

## 3. Maintenance Procedures

### Updating the Threat Feed
GuardianAI automatically pulls updates every 24 hours.
*   **Manual Trigger:** `POST /api/reload-model` (Auth required if configured).
*   **Source:** Defaults to GitHub. Override `THREAT_FEED_URL` in env vars for air-gapped setups.

### Backups
*   **What to backup:** The `/app/data` volume (SQLite DB).
*   **Frequency:** Daily recommended.
*   **Recovery:** Simply restore the file and restart the container.

---

## 4. Known Limitations
*   **Single Point of Failure:** In `docker-compose` setup, if the container dies, service stops. Use K8s/Swarm for HA.
*   **SQLite:** Not suitable for >10k req/sec writes. Migrate to PostgreSQL (Phase 5) if creating a massive cluster.
