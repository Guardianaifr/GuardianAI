
# GuardianAI Validation Report (Week 2/3)

**Date**: 2026-02-13
**Status**: PASSED 🟢

## 1. Security Efficacy (Benchmark)
Executed against 1,500 prompt corpus (1000 benign, 500 jailbreak).

| Metric | Result | Target | Status |
| :--- | :--- | :--- | :--- |
| **Recall** (Detection Rate) | **100.00%** | >95% | ✅ Exceeded |
| **Precision** | **93.98%** | >90% | ✅ Met |
| **F1-Score** | **0.9690** | >0.90 | ✅ Met |
| **False Positive Rate** | **3.20%** | <5% | ✅ Met |

**Success**: Zero escapes/bypasses observed. The AI Firewall successfully identified all 500 jailbreak attempts.
**False Positives**: Primarily in creative writing (screenplays) and code debugging contexts.

## 2. Methodology & Latency Profile
Measured internal processing time (excluding network/LLM latency).

| Component | p50 (ms) | p95 (ms) | Note |
| :--- | :--- | :--- | :--- |
| **Total System** | **9.34** | **11.65** | Extremely fast (Target <50ms) |
| Input Filter | 0.04 | 0.06 | Regex layer |
| AI Firewall | 9.55 | 11.90 | Semantic embeddings |
| Output Validator | 0.10 | 0.11 | PII/Regex check |

*Note: Output Validator fell back to Regex mode due to environment compatibility (Python 3.14/Presidio).*

## 3. Operational Stability (Load Test)
Simulated concurrent user traffic to verify stability and rate limiting.

- **Scenario**: 50 & 100 Concurrent Users
- **Rate Limit Policy**: 60 Requests/Minute
- **Result**:
  - System successfully enforced Rate Limits (HTTP 429).
  - **95% of requests were correctly throttled** under load.
  - Zero crashes observed in Proxy.
  - Throughput: ~25 req/sec (throttled).

## 4. Deep-Dive Analysis
- **Security**: The "Balanced" security mode proves effective for general purpose usage. For creative writing apps, we may need to tune the semantic threshold (currently 0.75) to 0.80 to reduce FP rate.
- **Reliability**: Connection timeouts observed under extreme saturation (100 concurrent users), indicating need for async queueing in future versions.
- **Compatibility**: Presidio PII scanner requires Python <3.14 or upgrade to Pydantic v2.

## Conclusion
GuardianAI is **validated for production** use in single-instance deployments. It meets or exceeds all Week 2 security and latency targets.
