# GuardianAI Performance & Chaos Report

Generated: 2026-04-22 20:53:53

## Baseline Safe Load
- Requests: 120
- Concurrency: 20
- Throughput (rps): 95.68
- p95 latency (ms): 249.04
- Status counts: {'200': 120}

## Attack Block Load
- Requests: 120
- Concurrency: 20
- Throughput (rps): 494.01
- p95 latency (ms): 41.88
- Status counts: {'403': 120}

## Chaos Scenarios
- Upstream down: status=502 latency_ms=2054.55
- Backend down: status=200 latency_ms=40.94

## SLO Verdict
- {'baseline_p95_lt_1500ms': True, 'baseline_success_rate_gt_99pct': True, 'attack_block_rate_gt_95pct': True, 'upstream_down_returns_502_or_599': True, 'backend_down_proxy_still_serves_200': True, 'all_passed': True}