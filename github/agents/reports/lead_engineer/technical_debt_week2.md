# Technical Debt Report (Cycle 2)

**Date**: Feb 13, 2026
**Auditor**: Lead Engineer

## ðŸ”´ High Priority
### 1. Invasive Instrumentation
- **Issue**: The `timings` dictionary is passed explicitly through all helper methods (`_check_ai_firewall`, `_process_output_validation`, etc.).
- **Impact**: Pollutes method signatures, making them harder to test and maintain. Breaks encapsulation.
- **Fix**: Use a Python decorator (`@measure_latency`) or a Context Manager to capture timings implicitly.

## ðŸŸ¡ Medium Priority
### 2. Hardcoded Pydantic Dependency in Presidio
- **Issue**: `OutputValidator` has a hard dependency on `presidio-analyzer` which conflicts with Python 3.14/Pydantic v2.
- **Impact**: Warnings in logs, fallback to regex-only mode on some environments.
- **Fix**: Abstract the PII scanner behind an interface adapter to support swapping implementations (Presidio vs. Regex vs. GLiNER).

### 3. Mock Drift in Profiling
- **Issue**: `tools/profile_latency_week2.py` mocks `requests` to isolate components.
- **Impact**: While good for component profiling, it doesn't catch network-level issues or actual HTTP overhead.
- **Fix**: Add an integration test mode that runs against a real downstream mock server.

## ðŸŸ¢ Low Priority
### 4. Configuration Sprawl
- **Issue**: `GuardianProxy` reads config dicts deeply (`config.get('security_policies', {}).get(...)`).
- **Impact**: Prone to typos and default value inconsistencies.
- **Fix**: Migrate to a typed configuration object (Pydantic model) for the entire app config.

