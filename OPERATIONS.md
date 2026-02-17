# GuardianAI Operations Guide

This document outlines the operational procedures for maintaining a healthy GuardianAI deployment.

## 1. State Management & Resource Limits

### Multi-turn Context Buffer
- **Component**: `GuardianProxy`
- **Behavior**: Stores the last 5 prompts per session ID (or IP) for semantic analysis.
- **Limit**: 5 prompts per session.
- **Cleanup**: Currently, state persists in memory until process restart. In high-traffic environments, monitor memory usage of the `guardian_proxy` process.
- **Recommendation**: For production, use a redis-backed session store if persistence across restarts or multi-instance sync is required.

### Rate Limiter Buckets
- **Component**: `RateLimiter`
- **Behavior**: Uses a Token Bucket algorithm per IP in memory.
- **Cleanup**: In-memory dictionary grows with unique IPs.
- **Recommendation**: Periodic restarts or migration to a distributed rate limiter (Redis) for large-scale deployments.

## 2. Log Management & Archival

### Log Locations
- **Standard Out**: Logs are emitted to STDOUT/STDERR.
- **Log Files**: In production (Docker/Systemd), logs are managed by the host system (e.g., `journalctl` or Docker log driver).

### Maintenance (Cleanup)
- **Rotation**: Ensure log rotation is configured (e.g., via `logrotate` on Linux).
- **Retention**: Keep security logs for a compliance-appropriate retention window.

## 3. Backup & Restore Procedures

### Configuration Backup
The most critical state in GuardianAI is the `guardian/config/` files and environment variables.
- **Backup Command**:
  ```bash
  tar -czvf guardian_config_backup_$(date +%F).tar.gz ./config/
  ```
- **Frequency**: Backup after any configuration change.

### Threat Feed Persistence
Threat feeds are updated dynamically in memory.
- **Restore**: On restart, GuardianAI will automatically fetch the latest community patterns from the configured URL.

### Telemetry Data
If using the Guardian Dashboard/Backend:
- **Database**: Ensure the backend database (SQLite (default)) has an automated backup schedule (e.g., WAL-G or pg_dump).

## 4. Monitoring & Alerts

### Health Checks
- **Endpoint**: `GET /health`
- **Threshold**: Response code 200 within 500ms.

### Metric Thresholds
- **CPU**: Alert if > 80% for 5 mins.
- **Memory**: Alert if > 2GB (for small deployments).
- **Latency (p95)**: Alert if > 100ms.


