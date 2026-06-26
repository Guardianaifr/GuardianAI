# Cost Abuse Simulation Report

Date: March 11, 2026
Status: Completed

## Objective

Validate that synthetic wallet-drain behavior triggers:

- anomaly alerting (`cost_abuse_detected`)
- session quarantine enforcement (`session_quarantined`)

## Implementation Scope

- Added rolling-window anomaly detector for token/cost spikes.
- Added quarantine enforcement at request ingress (active quarantine gate).
- Added post-response accounting for token/cost usage and immediate quarantine trigger.
- Added backend analytics ingestion support for cost-abuse event types.

## Synthetic Scenario

Scenario: repeated high-token requests in a short window for a single session.

Test settings used:

- `min_events = 2`
- `max_tokens_per_window = 40`
- upstream response usage per call: `total_tokens = 25`

Expected behavior:

1. First request: allowed.
2. Second request: threshold exceeded, quarantine activated.
3. Subsequent requests: blocked by active quarantine gate.

Observed behavior:

- First request returned `200`.
- Second request returned `403` with quarantine message.
- Quarantine state persisted for follow-up requests within quarantine TTL.

## Verification Evidence

Commands and outcomes:

- `pytest -q tests/security/test_cost_abuse_detector.py` -> `2 passed`
- `pytest -q tests/runtime/test_interceptor.py::test_proxy_blocks_when_cost_abuse_quarantine_active tests/runtime/test_interceptor.py::test_proxy_quarantines_on_wallet_drain_pattern` -> `2 passed`
- `pytest -q` -> `175 passed`
- `python tools/run_missing_security_validation.py` -> passed (`sast_findings: 0`)
- `python tools/run_hardening_validation.py` -> completed (expected sample findings in hardening fixture data)
- `python tools/run_performance_chaos_validation.py` -> passed
- `python tools/check_security_slo.py` -> passed (`all_passed: true`)

## Result

Cost-abuse protection is operational and verified against synthetic wallet-drain behavior with quarantine + alerting.
