# AI Security Backlog (2026 Q1)

Source: `suggestions.txt` gap analysis (March 2026)  
Status key: `planned`, `in_progress`, `completed`

## P0 (Immediate)

1. Agentic/MCP Security Controls - `completed`
- Add agent identity and execution identity headers.
- Add parent->child hop authorization checks.
- Add task scope -> tool allowlist enforcement.
- Add agent/execution kill-switch and global pause.
- Files:
  - `guardian/security/agentic_controls.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/runtime/test_interceptor.py`

2. RAG Indirect Prompt Injection Controls - `completed`
- Retrieval document sanitization and instruction stripping.
- Chunk-level trust scoring and denylist tagging.
- Cross-source contamination detection.
Status update:
- Core request-time RAG guard implemented:
  - indirect injection detection in retrieved chunks
  - context stuffing/oversized chunk controls
  - embedding dump pattern blocking
- Integration files:
  - `guardian/security/rag_guard.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/runtime/test_interceptor.py`
- Remaining expansion:
  - trust scoring and source reputation
  - cross-source contamination heuristics
  - retrieval-time sanitization pipeline

3. Multimodal Input Scanning Baseline - `completed`
- OCR pass for images/PDF to detect hidden instructions.
- Audio transcript pre-filter for injection patterns.
- MIME-aware payload scanner pipeline.
Status update:
- Baseline multimodal request guard implemented:
  - image/PDF/audio extracted text inspection
  - multimodal prompt-injection detection
  - multimodal exfiltration-intent detection
  - disallowed attachment MIME enforcement
  - payload text/segment budget limits
- Integration files:
  - `guardian/security/multimodal_guard.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/runtime/test_interceptor.py`
- Remaining expansion:
  - integrated OCR/transcription adapters for binary uploads
  - malware/AV scanning for attachments
  - per-tenant multimodal sensitivity profiles

## P1 (Near Term)

4. Live SIEM Integration (beyond export) - `completed`
- Real-time stream adapter with retries, dead-letter queue, and mapping packs.
Status update:
- Live SIEM router implemented with async dispatch and resilient delivery:
  - transport modes: `file`, `http`, `both`
  - retry/backoff controls
  - dead-letter queue JSONL on delivery failure
  - optional auth header/token for SIEM endpoint posting
  - non-blocking backend telemetry path using router queue
- Integration files:
  - `backend/siem.py`
  - `backend/main.py`
  - `tests/backend/test_siem_format.py`
- Remaining expansion:
  - batch replay worker for dead-letter recovery
  - richer SIEM mapping packs (Splunk/Sentinel/Elastic presets)

5. False-Positive Feedback Loop - `completed`
- Analyst review queue for blocked-but-benign samples.
- Per-tenant sensitivity tuning profile.
- Corpus curation and regression gates.
Status update:
- Implemented runtime feedback-loop and tenant tuning baseline:
  - reviewed false-positive prompt hash allowlist (tenant + event-family scoped, TTL-bound)
  - per-tenant security mode and block-reason tuning (`strict|balanced|lenient`)
  - proxy integration to bypass selected block families only when explicitly allowlisted
- Integration files:
  - `guardian/security/feedback_loop.py`
  - `guardian/security/tenant_sensitivity.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/security/test_feedback_loop.py`
  - `tests/security/test_tenant_sensitivity.py`
  - `tests/runtime/test_interceptor.py`
- Remaining expansion:
  - analyst UI/API workflow for approve/reject lifecycle
  - feedback corpus promotion pipeline and regression auto-generation
  - confidence-weighted per-tenant adaptive thresholds

6. Model Provenance in Supply Chain - `completed`
- Track model checkpoint origin/hash/fine-tune lineage.
- Extend SBOM/manifest to include model artifacts.
Status update:
- Implemented model provenance verification in supply-chain module:
  - model artifact manifest hash verification
  - missing artifact and mismatch detection
  - support for legacy map format and structured weight entries
- Extended SBOM generation:
  - optional `--model-manifest` input
  - model provenance section included in SBOM validation output
  - optional hard gate via `--enforce-model-provenance`
- Added dedicated provenance verification tool:
  - `tools/verify_model_provenance.py`
- Integration files:
  - `guardian/security/supply_chain.py`
  - `tools/generate_sbom.py`
  - `tools/verify_model_provenance.py`
  - `tests/security/test_supply_chain_hardening.py`
- Remaining expansion:
  - include signed model lineage metadata (dataset hash, fine-tune job IDs, signer identity)
  - integrate provenance checks in CI release gate by default

## P2 (Expansion)

7. Behavioral Cost Abuse Intelligence - `completed`
- Slow-drain multi-session anomaly models per tenant.
Status update:
- Extended cost-abuse detector with tenant-level behavioral intelligence:
  - cross-session rolling-window aggregation per tenant
  - active-session cardinality thresholding
  - slow-drain detection for token and cost budgets across sessions
  - session contribution minimums to reduce false positives
- Runtime integration:
  - interceptor now passes `tenant_id` into usage registration path
- Integration files:
  - `guardian/security/cost_abuse.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/security/test_cost_abuse_detector.py`
- Remaining expansion:
  - seasonality-aware baselines per tenant
  - detection from cache-hit abuse patterns
  - risk scoring with adaptive thresholds by tenant maturity tier

8. Context/Memory Poisoning Defenses - `completed`
- Memory item trust boundaries and poisoning quarantine.
Status update:
- Implemented session memory poisoning guard baseline:
  - poison-pattern detection in prompts entering session memory
  - per-session memory quarantine window on poison detection
  - runtime enforcement before downstream model checks
  - memory entry bounding per session
- Integration files:
  - `guardian/security/memory_guard.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/security/test_memory_guard.py`
  - `tests/runtime/test_interceptor.py`
- Remaining expansion:
  - source trust labels for memory entries (tool/user/system provenance)
  - selective memory eviction/repair instead of full session quarantine
  - cross-session memory poisoning correlation

9. Hallucination Risk Enforcement - `completed`
- Implemented structured output assurance guard:
  - JSON output enforcement (`require_json_output`)
  - required schema field checks (`required_json_fields`)
  - citation grounding gate with URL validation and minimum citation count
  - optional confidence threshold enforcement for high-stakes responses
- Runtime integration:
  - output assurance validation in proxy response path
  - enforce/audit mode behavior
  - telemetry event emission on assurance block (`output_assurance_block`)
- Integration files:
  - `guardian/security/output_assurance.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tests/security/test_output_assurance.py`
  - `tests/runtime/test_interceptor.py`

10. Public Benchmark Alignment - `completed`
- Implemented public benchmark alignment pipeline with adapters for:
  - HarmBench attack-block scoring
  - AdvBench attack-block scoring
  - GAIA task-success scoring
- Added benchmark gate and score publishing workflow:
  - JSON verdict artifact
  - Markdown summary artifact
  - composite weighted score check
- Integrated public benchmark gate into missing-security validation pack.
- Integration files:
  - `guardian/security/public_benchmark.py`
  - `tools/run_public_benchmark_alignment.py`
  - `tools/run_missing_security_validation.py`
  - `tests/security/test_public_benchmark_alignment.py`
  - `tests/data/public_benchmark_sample.json`
  - `artifacts/performance/public_benchmark_targets.json`

11. Output Watermarking - `completed`
- Implemented signed output watermarking control:
  - response watermark injection for JSON payloads
  - HMAC-based signature over canonical response body
  - configurable watermark field/key/key-id
  - enforce/audit mode behavior
- Added verification utility for watermark integrity checks:
  - `tools/verify_output_watermark.py`
- Runtime integration:
  - watermark applied on outbound proxy responses after output validation
  - telemetry events for watermark apply/block paths
- Integration files:
  - `guardian/security/output_watermark.py`
  - `guardian/runtime/interceptor.py`
  - `guardian/config/config.yaml`
  - `tools/verify_output_watermark.py`
  - `tests/security/test_output_watermark.py`
  - `tests/runtime/test_interceptor.py`

12. Differential Privacy for Aggregated Analytics - `completed`
- Implemented differential privacy controls for aggregated analytics:
  - Laplace-noise based protection for aggregate analytics counts/rates
  - configurable env controls:
    - `GUARDIAN_DP_ENABLED`
    - `GUARDIAN_DP_EPSILON`
    - `GUARDIAN_DP_SEED` (deterministic testing)
  - endpoint-level override support via `/api/v1/analytics?dp=<bool>&epsilon=<float>`
- Added DP benchmark utility and report publishing:
  - `tools/run_dp_analytics_benchmark.py`
  - outputs JSON + markdown benchmark artifacts
- Added tests covering:
  - backend DP-enabled analytics behavior
  - backend DP override-disable behavior
  - DP noise helper behavior + epsilon/error trend benchmarking
- Integration files:
  - `backend/main.py`
  - `guardian/security/differential_privacy.py`
  - `tools/run_dp_analytics_benchmark.py`
  - `tests/backend/test_tenant_isolation_backend.py`
  - `tests/security/test_differential_privacy.py`
