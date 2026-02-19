# ðŸš€ GuardianAI Latency Profile (Cycle 2)

**Date**: 2026-02-13
**Sample Size**: 1500 requests

## ðŸ“Š Summary Metrics
- **p50 (Median)**: 8.84ms
- **p95**: 11.96ms
- **p99**: 17.37ms
- **Max**: 5651.96ms

## ðŸ§© Component Breakdown

### Input Filter
- Calls: 1500
- p50: 0.0285ms
- p95: 0.0390ms
- p99: 0.0446ms

### Threat Feed
- Calls: 1389
- p50: 0.0003ms
- p95: 0.0005ms
- p99: 0.0007ms

### Ai Firewall
- Calls: 1389
- p50: 8.6030ms
- p95: 12.0517ms
- p99: 17.1743ms

### Output Validator
- Calls: 1188
- p50: 0.0947ms
- p95: 0.1095ms
- p99: 0.1221ms
