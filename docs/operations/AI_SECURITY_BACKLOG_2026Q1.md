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
  - richer SIEM mapping packs (Splunk/Microsoft SIEM/Elastic presets)

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

13. Financial Logic / Web3 Security Gaps - `partial` (2 closed, 2 blocked-on-prerequisite)
- FL_002 (Yield/APY): **CLOSED** — real external validation via DefiLlama API with TTL caching implemented in `guardian/audit/remediation/crypto_guard.py`. Fails closed on API timeout.
- FL_003 (Trading Signals): **CLOSED** — real source verification requiring Pyth/Chainlink ECDSA signature block; prompts that merely mention an exchange name without a verifiable signature are blocked.
- FL_005 (Governance): **BLOCKED** — requires session-wallet auth prerequisite (caller's on-chain address must be verifiably bound to the session) before `getVotes()` lookup is meaningful. Permanently blocked until that prerequisite is built. Does NOT silently fail open — the current implementation rejects all governance vote-cast instructions because the governance ledger is empty (fails closed by design after the fix; the prior failure was failing closed by accident).
- FL_008 (Slippage): **BLOCKED** — requires a 1inch API key for production DEX liquidity depth queries. The intent gate and normalization logic is implemented; the live enforcement path is gated on the API credential. Fails closed (rejects the slippage-modification instruction) when the DEX aggregator is unavailable.
- See `../audits/FL_pillar_gap_and_fix_spec.md` for full spec, structural decisions, and open TTL-cache timing question.

14. Agentic Security Fail-Open State - `accepted-risk` (documented, no code change planned)
- The `agentic_security` parent module currently defaults to `enabled: False`, completely bypassing its sub-controls (`rag_security`, `agentic_controls`).
- **Sub-controls (rag_security, agentic_controls) fail-open defaults:** CLOSED — `rag_security` and `agentic_controls` sub-controls were each independently fixed to fail closed by default (i.e., if `agentic_security` parent is enabled, the sub-controls no longer silently pass through).
- **Parent `agentic_security` flag:** INTENTIONALLY ACCEPTED as opt-in. The current architecture cannot safely default to enabled because `require_agent_id` unconditionally blocks any request without an `X-Guardian-Agent-Id` header. In mixed agentic/non-agentic environments, enabling this would break all standard human traffic.
- **Design prerequisite for a real fix:** Auto-detect agentic vs. human traffic and only enforce agentic controls conditionally — OR default `require_agent_id` to `False` so non-agentic traffic passes by default. This is a design decision deferred to a future session.
- **Current risk posture:** Any deployment that does NOT enable `agentic_security: true` in config.yaml gets no agentic security enforcement. This is documented and explicitly accepted, not silently present.

---

## On-Chain Contract Audit (August 2026)

15. On-Chain Smart Contract Security Audit (6 contracts) - `completed`

All six on-chain EVM contracts (Features 33–38) underwent their first dedicated security audit in August 2026.

**Findings and resolution:**

| ID | Contract | Severity | Finding | Status | Commit |
|---|---|---|---|---|---|
| TF-1 | ThreatFeedRegistry | HIGH | AccessControl/role bypass — deployer EOA retains write access post-ownership-transfer | FIXED | `cdf52b3f` |
| TF-2 | ThreatFeedRegistry | MEDIUM | O(n) linear scan in removeAddress/removeStringAddress | FIXED | `c36d9e50` |
| TF-3 | ThreatFeedRegistry | MEDIUM | No hard cap on evmAddresses/stringAddresses array cumulative size | FIXED | `c36d9e50` |
| TF-4 | ThreatFeedRegistry | LOW | pause/unpause onlyOwner while writes were onlyRole — asymmetric access | RESOLVED BY TF-1 | `cdf52b3f` |
| RA-1 | RiskAttestation | MEDIUM | Missing Pausable (only contract of 5 with no emergency stop) | FIXED | `798218ed` |
| RA-2 | RiskAttestation | LOW | No ReentrancyGuard on attest() | ACKNOWLEDGED / NOT FIXED — attest() has no external calls; vector does not exist | — |
| RA-3 | RiskAttestation | MEDIUM | No grade allowlist — arbitrary string accepted | FIXED | `798218ed` |
| RA-4 | RiskAttestation | LOW | Silent attestation overwrite — no event distinction | FIXED | `798218ed` |
| IR-2 | InterlockRegistry | LOW | No revoke/update mechanism — bad registration is permanent | FIXED (soft-revoke) | `9f8bbfbb` |
| IL-1 | InsuranceLedger | LOW | Misleading error: CertificateNotFound used for zero _certId input guard | FIXED | `b24883e9` |
| IL-2 | InsuranceLedger | LOW | Check ordering: cap check before input validation allows info leak via error type | FIXED | `b24883e9` |
| IL-3 | InsuranceLedger | INFO | certificateIds unbounded array, no pagination for off-chain readers | FIXED | `b24883e9` |
| CA-1 | CortexAnchor | INFO | getAgentCommitments() O(n) unbounded read | DOCUMENTED (no code change — caller-borne view cost, zero on-chain callers) | `b24883e9` |
| CA-2 | CortexAnchor | INFO | verifyInclusion() O(n) proof array | DOCUMENTED (no code change — pure function, zero on-chain callers) | `b24883e9` |
| naming-conv | All 5 contracts | INFO | Slither naming-convention: underscore-prefix params | ACKNOWLEDGED / NOT FIXED — consistent style, ABI-breaking to rename, zero security impact | — |
| PassportSBT | PassportSBT | (hardening) | ReentrancyGuard belt-and-suspenders on mint() | ADDED | `dd33270a` |

**Hardhat suite:** 159/159 passing across 10 contract suites, 0 regressions.

---

## Features Not Yet Audited (as of August 2026)

The following whitepaper-claimed features have NOT yet been through a dedicated security audit. This list is maintained explicitly so they are not forgotten or assumed audited by association with the work above.

| Feature | Whitepaper Claim | Audit Status |
|---|---|---|
| F-01: Embedding Firewall (semantic similarity) | "Catches semantically equivalent attacks" | **DONE (August 2026)** — Non-English evasion fixed via translation-adapter (Approach A). See F2 section below. |
| F-02: Multi-modal MIME guard | "OCR/audio injection detection" | Not audited |
| F-03: RAG injection guard | "Chunk-level trust scoring" | Partially audited (core guard reviewed; trust-scoring/cross-source not) |
| F-04: Tool-Call Policy Engine | Allow/deny enforcement | Not audited |
| F-05: PII Redaction | Regex + NER redaction | Not audited |
| F-06: Cost Abuse Detection | Slow-drain multi-session models | Not audited |
| F-07: Memory Poisoning Guard | Session memory quarantine | Not audited |
| F-08: Output Assurance | JSON enforcement, citation grounding | Not audited |
| F-09: Output Watermarking | HMAC signature on response body | Not audited |
| F-10: Differential Privacy Engine | Laplace-noise analytics | Not audited |
| F-11: Supply Chain / Model Provenance | Artifact hash verification | Not audited |
| F-12: Hallucination / GAIA alignment | Output grounding enforcement | Not audited |
| F-13: Red/Purple Brain Agent | Autonomous rule generation | Not audited |
| F-14: SIEM Integration | Async retry/dead-letter queue | Not audited |
| F-15: False-Positive Feedback Loop | Tenant sensitivity tuning | Not audited |
| F-16: Public Benchmark Alignment | HarmBench/AdvBench/GAIA scoring | **Corrected (August 2026)** — see F28 section below |
| F-17: Tenant Isolation (backend) | Cross-tenant data boundaries | Not audited |
| F-18: SSH Tunnel / Generic Auth Proxy | Remote access security | Not audited |
| F-19: Adversarial Self-Correction | Red-team-driven rule updates | Not audited |
| F-20: Custom NER Models | Fine-tuned entity recognition | Not audited |

---

## F2 — Semantic Firewall Multilingual Evasion `completed (August 2026)`

**Root Cause:** `all-MiniLM-L6-v2` is English-only. French jailbreak scored **0.43** (below 0.55 balanced threshold). Same prompt in English scores **0.85**. All thresholds were calibrated against English text; non-English input bypassed the ML layer entirely.

**Fix: Approach A — Translation Adapter Layer** (`guardian/guardrails/translation_adapter.py`)
- `langdetect` (< 5ms, already in requirements.txt) gates on `lang != 'en'`
- `deep-translator==1.11.4` (pure-Python, uses `requests` already pinned; no API key required) translates to English
- Translated text passes into the **unmodified** `all-MiniLM-L6-v2` firewall at the **unmodified** thresholds (0.45/0.55/0.70)
- **Fail-closed contract:** translation API error / timeout / empty result / unsupported language → request BLOCKED (`translation_failure` event logged). No silent pass-through path exists.

**Why not Approach B (multilingual model swap):** The swap was tried and reverted — it caused catastrophic false positives ("Translate this to Spanish" → 0.70; professional email → 0.65) because the new embedding space invalidated the existing calibration, and no automated calibration script exists in this codebase.

**Verification (real scored output from ai_firewall):**
- French jailbreak raw score WITHOUT translation: `0.4322` → NOT blocked (evasion confirmed)
- English equivalent score (what translation gate sends): `0.8510` → BLOCKED ✓
- `fw.is_malicious(French jailbreak, mocked translation)`: `True` ✓
- Fail-closed (translation RuntimeError): `is_malicious` returns `True` ✓
- Spanish, German, Mandarin jailbreaks: all `True` ✓
- Benign false-positive set (professional email, language-learning): `False` ✓

**Known pre-existing FP (not a regression):** "Translate this to Spanish" scores 0.59/task_switching in the base English ML model — this FP exists regardless of F2. The translation adapter correctly identifies this as English (`langdetect → 'en'`) and does not translate it, introducing zero delta.

**Files changed:**
- `guardian/guardrails/translation_adapter.py` [NEW]
- `guardian/guardrails/ai_firewall.py` — added step 0c translation gate in `is_malicious()`
- `requirements.txt` — added `deep-translator==1.11.4`
- `tests/guardrails/test_f2_translation_adapter.py` [NEW — 19 tests, 19 passed]

---

## Phase 4 Audit Findings — August 2026


Items identified during the Phase 4 whitepaper-vs-code audit (Features 18–26). Each entry records current implementation status, open gaps, and deferred work items.

---

### F18 — Red-Team Automated Probe Loop ✅ DONE

**Audit finding (August 2026):** Whitepaper claimed probes "fire against the live AI" and measure real model behavior. Code only called `input_filter.check_prompt(payload)` — zero LLM contact.

**Whitepaper corrected and updated (August 2026):** F18 description in `WHITEPAPER.md` and `../whitepaper/WHITEPAPER_PUBLIC.md` rewritten to accurately describe the 3-stage pipeline.

**Implementation: `FEAT-RED-LLM` — DONE (August 2026)**

The `run_probe_cycle()` method in `brain/red_probe.py` was fully rewritten with a genuine 3-stage pipeline:

| Stage | What happens | API cost |
|-------|-------------|----------|
| **1 — Input filter fast-path** | `input_filter.check_prompt(payload)` — if blocked, discard immediately | Zero |
| **2 — Real upstream LLM call** | HTTP POST to configurable `red_probe_target_url` (separate from production) | One call per filter-bypassing probe |
| **3 — Response classification** | 16-pattern keyword refusal detector classifies LLM response | Zero additional calls |

**Outcome taxonomy:**

| Outcome | Meaning | Severity | Triggers auto-patch? |
|---------|---------|----------|---------------------|
| `filter_blocked` | Filter caught it (no finding emitted) | — | No |
| `full_bypass` | Filter passed + LLM complied | high | **Yes** |
| `filter_bypass_model_refused` | Filter passed + LLM refused | medium | No |
| `filter_bypass_only` | No target configured; filter gap only | medium | No |

**Design decision — separate `red_probe_target_url`:** Production upstream is excluded from the probe loop to avoid sharing rate limits, API cost, or conversation context with real user traffic. Default: no target configured → Stage 2 skipped (safe, zero-cost, partial findings only).

**Config keys** (`brain:` YAML section): `red_probe_interval_seconds` (default: 1800), `red_probe_target_url`, `red_probe_upstream_key`, `red_probe_timeout` (default: 15s).

**Error handling:** Any upstream failure (timeout, 5xx, connection error) is caught and logged; brain background thread never crashes on a failed probe call.

**Orchestrator integration:** `orchestrator.run_once()` passes only `OUTCOME_FULL_BYPASS` findings to purple-heal — partial findings are informational and never trigger auto-patch.

**Tests:** `tests/brain/test_red_probe_llm.py` — 21 tests, all passing. Key tests:
- `test_blocked_probe_calls_llm_zero_times` — call-count assert: filter-blocked probes never reach `_call_llm`
- `test_selective_filter_only_calls_llm_for_allowed_probes` — LLM called exactly 1× for 1 allowed probe out of 2
- All 4 outcome paths covered; error resilience under timeout/5xx/connection error/filter exception

**Files:** `guardian/brain/red_probe.py` (rewrite), `guardian/brain/orchestrator.py` (config wiring + outcome filter), `tests/brain/test_red_probe_llm.py` (new), `tests/brain/test_orchestrator.py` (3 tests updated to mock `run_probe_cycle`)

**Commits:** `c229325d` (FEAT-RED-LLM rewrite), `09aec84e` (orchestrator test fix)

---

### F25 — Multi-Tenant Isolation `completed (partial)`

**Audit finding:** Whitepaper claimed "Hard isolation of data, session state, and rate limit buckets per tenant." Code delivers in-process key-prefix namespacing within shared Python in-memory dicts — logical isolation, not hard isolation.

**Completed (August 2026):**
- Whitepaper corrected in `WHITEPAPER.md`, `../whitepaper/WHITEPAPER_PUBLIC.md`, `WHITEPAPER Update.md` — "hard isolation" language removed, accurate description + Phase 4 audit note added.
- Concurrent cross-tenant test suite added: `tests/security/test_tenant_isolation_concurrent.py` — 14 tests, all green.
- **FEAT-TENANT-INMEM-HARDEN completed**: Per-tenant `threading.Lock()` instances with overflow fallback + `max_tracked_sessions` cap with LRU eviction and quarantine exemption. Closes OOM and contention risks.

**Open gaps (confirmed, empirically proven):**

| Gap | Risk | Evidence |
|-----|------|----------|
| Quarantine/session-risk state is node-local only | HIGH — multi-node deployments fracture rate-limit enforcement | Architectural — no test can prove cross-node consistency without Redis |

**Deferred implementation items:**

1. **`FEAT-TENANT-REDIS` (P2 — future):** Migrate `CostAbuseDetector._events` and `_quarantined_until` to Redis with per-tenant key prefix (`guardian:tenant:<id>:sess:<sid>`) and TTL-based expiry. Closes multi-node fracture risk. Pre-conditions: `redis` added to `requirements.txt`; `GUARDIAN_TENANT_REDIS_URL` env var documented in `.env.example`, `docker-compose.yml`, and deployment docs; fail-closed behaviour defined (mirror pattern from `backend/main.py` `GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN`).

**Files:**
- `guardian/security/cost_abuse.py` (primary implementation target for both items)
- `guardian/security/tenant_isolation.py` (no mutable runtime state — no Redis migration needed)
- `guardian/security/tenant_sensitivity.py` (static config lookup — no changes needed)
- `tests/security/test_tenant_isolation_concurrent.py` (update OOM assertion when INMEM-HARDEN lands)

---

### F19 — Blue-Team Adaptive Session Hardening `in_progress`

**Audit finding:** Whitepaper claimed "automatically tightens rate limits" and "reduces output permissions." Neither was implemented. `BlueAdaptAgent` was wired (risk scoring → strict mode → honeypot → revoke) but four advanced classes were dead.

**Whitepaper corrected (August 2026):** False rate-limit and output-permission claims removed from all 3 docs.

**Per-class decisions:**

| Class | What it does | Quality | Wire or Defer | Reasoning |
|-------|-------------|---------|---------------|-----------|
| `SessionVelocityTracker` | Sliding-window RPS anomaly per session; `record()` returns bool | Production-ready: sliding window with prune, configurable max_rps | **✅ DONE — `FEAT-BLUE-ADVANCED` (August 2026)** | Wired in `observe_prompt()`: adds +1 risk delta when velocity is anomalous. |
| `AdaptiveCooldown` | Exponential backoff per session (base × multiplier^violations, capped) | Production-ready: violation count, FIFO cooldown_until, reset() | **✅ DONE — `FEAT-BLUE-ADVANCED` (August 2026)** | Wired in `get_action()` → returns `"cooldown"`; interceptor returns HTTP 429 + `Retry-After` header. |
| `GeoAnomalyDetector` | Distinct geo labels per hour; returns bool if > max_hops | Production-ready: 1h sliding window, distinct-set logic | **Defer — `FEAT-BLUE-GEO`** | Requires a geo-label input that the current request path does not provide (no IP→geo resolver). |
| `BehavioralFingerprint` | User-agent / lang / tz_offset drift detection across a session | Functional but limited: first-time always returns True (no binding), only 3 signals, no TTL/eviction | **Defer — `FEAT-BLUE-FINGER`** | Requires the request path to extract and pass user-agent, lang, and tz_offset consistently. |

**Implementation status:**

1. **✅ `FEAT-BLUE-ADVANCED` — DONE (August 2026):** `SessionVelocityTracker` wired into `observe_prompt()` (velocity anomaly → +1 risk delta); `AdaptiveCooldown` wired into `get_action()` (returns `"cooldown"` when active) and `interceptor.py` (HTTP 429 + `Retry-After` at both pre- and post-analysis gates). Config keys `blue_velocity_window_sec`, `blue_velocity_max_rps`, `blue_cooldown_base_seconds`, `blue_cooldown_max_seconds`, `blue_cooldown_multiplier` all wired. Tests: `tests/brain/test_blue_adapt_advanced.py`.
2. **`FEAT-BLUE-GEO` (P3):** Add IP→geo resolution (e.g. MaxMind GeoLite2) and wire `GeoAnomalyDetector`. Pre-condition: geo database license and loading strategy decided.
3. **`FEAT-BLUE-FINGER` (P3):** Extract `User-Agent` / `Accept-Language` / timezone from request headers and wire `BehavioralFingerprint.check()` in `observe_prompt`. Pre-condition: interceptor header-extraction refactor.

**Files:** `guardian/brain/blue_adapt.py`, `guardian/brain/orchestrator.py`, `guardian/runtime/interceptor.py`

---

### F22 — Session Revoke Enforcement & External IdP/JWT Integration `in_progress`

**Audit finding:** Whitepaper claimed "hash-based tracking" (dead: `TokenBlacklist`) and "system-wide" lockout (overstated: proxy-side is single-node, IdP-side is webhook-dependent). Core revocation flow IS wired: `BlueAdaptAgent.mark_revoked()` → `IdpRevocationClient.revoke()` via `CyberBrain.enforce_revocation()` in `orchestrator.py` lines 206–216.

**Whitepaper corrected (August 2026):** "hash-based tracking" and "system-wide" claims replaced with accurate scope description + single-node constraint note (mirroring F25 language).

**Per-class decisions:**

| Class | What it does | Quality | Wire or Defer | Reasoning |
|-------|-------------|---------|---------------|-----------|
| `TokenBlacklist` | Bounded FIFO dict: `token_hash → revoked_at`; `_MAX = 10,000`; FIFO eviction via sorted() | Production-ready: bounded, evicts, O(n log n) eviction (acceptable at 10k) | **Defer** — `FEAT-IDP-BLACKLIST` | **Same single-node gap as F25.** A JWT blacklist is only meaningful if it is checked on every request before forwarding. Wiring it in-memory has the same cross-node fracture problem as F25's `_quarantined_until` dict: a token revoked on node A is not blocked on node B. Wire only alongside `FEAT-TENANT-REDIS` (or a dedicated `GUARDIAN_REVOKE_REDIS_URL`) to share the blacklist across nodes. Until then, the wired `revoked_sessions` set in `BlueAdaptAgent` already provides session-level revocation locally. |
| `SessionBindingVerifier` | Binds JTI to session_id + client_ip at first presentation; `verify()` returns (bool, reason) | Production-ready: clean API, IP mismatch detection | **Defer** — `FEAT-IDP-BINDING` | Requires that Bearer tokens are parsed and their JTI extracted on every inbound request (not currently done at the interceptor level). `bind_session_identity()` in orchestrator already stores raw tokens — extend that to extract JTI and call `bind()`. Medium-scope change. |
| `MultiIdpFederation` | Priority-ordered fan-out to multiple `IdpRevocationClient` instances | Production-ready: clean registry, priority sort (minor bug: `sort(key=lambda n: priority)` uses the same `priority` value for all, not per-entry — sorts stably but not by individual priority) | **Defer** — `FEAT-IDP-MULTI` | `CyberBrain` currently only instantiates one `IdpRevocationClient`. `MultiIdpFederation` is additive: replace `self.idp_revocation = IdpRevocationClient(revoke_cfg)` with a federation. Config change required (list of IdP configs vs. single). Fix priority sort bug when wiring. |

**Note on TokenBlacklist vs F25:** These are architecturally the same problem. Both want cross-node in-memory revocation state. The correct sequence is: F25 `FEAT-TENANT-REDIS` first (shared Redis for tenant state) → then extend the same Redis connection for `FEAT-IDP-BLACKLIST` (separate key namespace `guardian:revoke:jwt:<hash>`). Do not wire `TokenBlacklist` in-memory as a standalone step — it would create a false sense of security at scale.

**Files:** `guardian/security/idp_revocation.py`, `guardian/brain/orchestrator.py`

---

### F23 — Honeypot/Deception Controls `in_progress`

**Audit finding:** Whitepaper claimed "wastes attacker reconnaissance time" (needs `AdaptiveDelaySimulator`, dead) and "passive collection of TTPs" (needs `AttackerProfiler` + `HoneypotAnalytics`, dead). Core honeypot IS wired: `HoneypotManager.build_response()` called from interceptor. Template rotation, per-session throttling, and nonce generation are active.

**Whitepaper corrected (August 2026):** Both false claims removed; active capabilities and unwired advanced classes accurately described.

**Per-class decisions:**

| Class | What it does | Quality | Wire or Defer | Reasoning |
|-------|-------------|---------|---------------|-----------|
| `AttackerProfiler` | Collects prompts (capped at 50), IPs (set), user-agents (set), interaction count per session | Production-ready: rolling prompt buffer, set dedup, TTL-free (needs pruning) | **✅ DONE — `FEAT-HONEY-PROFILE` (August 2026)** | Wired in `_build_honeypot_response()`: `record_interaction(session_id, prompt, client_ip, user_agent)` called on every honeypot engagement. Exposed via admin endpoint `GET /api/admin/honeypot/profiles`. |
| `HoneypotAnalytics` | Aggregate `total`, `per_session`, `per_path` interaction counters | Production-ready: simple counters, `top_sessions()` / `top_paths()` for dashboarding | **✅ DONE — `FEAT-HONEY-PROFILE` (August 2026)** | Wired in `_build_honeypot_response()`: `analytics.record(session_id, path)` called on every honeypot engagement. Exposed via admin endpoint `GET /api/admin/honeypot/analytics`. |
| `AdaptiveDelaySimulator` | Escalating delay per session: `base_ms × factor^count`, capped at `max_ms` | Production-ready: clean exponential, per-session counter | **Defer — `FEAT-HONEY-DELAY`** | `asyncio.sleep()` / `time.sleep()` in the synchronous Flask request path would block the WSGI thread. Needs either (a) async WSGI migration (major scope) or (b) the response to include a `Retry-After` header. Defer until async migration or header-based approach is scoped. |
| `CanaryTokenManager` | Generates `GUAR-CANARY-<sha256[:16]>` tokens; `check_triggered(text)` scans for presence | Production-ready: deterministic generation, trigger tracking, count APIs | **Defer — `FEAT-HONEY-CANARY`** | Requires injecting canary tokens into honeypot response bodies AND checking model responses for token leakage in the output validator. Meaningful scope — the response template must be made token-aware. |
| `DecoyCredentialRotator` | Rotating fake credentials with realistic prefixes (`sk-fake`, `AKIA-FAKE`, `ghp_fake`, `xoxb-fake`) + session-scoped suffix | Functional: deterministic, prefix rotation. Issue: uses `md5` for suffix generation (not security-critical here — these are fake credentials — but worth noting) | **Defer — `FEAT-HONEY-CANARY`** | Same scope as `CanaryTokenManager` — both require response-body injection. Group with canary item. **Replace `md5` with `sha256[:20]` when wiring** (`guardrails/honeypot.py` L202: `hashlib.md5(…)` → `hashlib.sha256(…)`). |

**Implementation status:**

1. **✅ `FEAT-HONEY-PROFILE` — DONE (August 2026):** `AttackerProfiler.record_interaction()` and `HoneypotAnalytics.record()` wired inside `_build_honeypot_response()` in `interceptor.py`. Admin endpoints `GET /api/admin/honeypot/profiles` and `GET /api/admin/honeypot/analytics` registered and protected by admin-token auth. Tests: `tests/unit/test_honeypot_profile.py`.
2. **`FEAT-HONEY-DELAY` (P3):** Scope async WSGI migration or header-based delay signaling before wiring `AdaptiveDelaySimulator`.
3. **`FEAT-HONEY-CANARY` (P3):** Wire `CanaryTokenManager` + `DecoyCredentialRotator` with token-aware response template injection and output-validator canary detection. **Must replace `md5` with `sha256[:20]` in `DecoyCredentialRotator.next_credential()` (`guardrails/honeypot.py` L202) when wiring.**

**Files:** `guardian/guardrails/honeypot.py`, `guardian/runtime/interceptor.py`

---

### F28 — Section 6 Whitepaper Benchmark Correction `completed (August 2026)`

**Finding:** A Phase 5 audit (August 2026) confirmed that all Section 6 benchmark numbers in WHITEPAPER.md, ../whitepaper/WHITEPAPER_PUBLIC.md, and `WHITEPAPER Update.md` traced to a synthetic test fixture (`tests/data/public_benchmark_sample.json`, April 2026) with no real dataset evaluation behind it. The `public_benchmark.py` module is dead code with no runtime caller. The discrepancy was already known internally (acknowledged in `../architecture/FEATURE_BENCHMARK_ANALYSIS.md` section 7e) but never propagated to the public-facing whitepaper.

**Numbers replaced — old vs. new:**

| Metric | Old (fabricated) | New (real source) | Source file |
|---|---|---|---|
| HarmBench block rate | 97.0% | 72.8% strict / 57.8% balanced | `definitive_benchmark_v4.json` (2026-08-08) |
| AdvBench block rate | 94.0% | 99.0% strict / 95.6% balanced | `definitive_benchmark_v4.json` (2026-08-08) |
| Security-gate Tier 1+2 | (not in table) | 97.6% strict / 90.7% balanced | `definitive_benchmark_v4.json` (2026-08-08) |
| Grand total 8 datasets | (not in table) | 76.6% strict / 58.5% balanced | `definitive_benchmark_v4.json` (2026-08-08) |
| GAIA alignment | 86.0% | *removed — no real source* | (none found in repo) |
| Composite benchmark | 93.6% | *removed — derived from fabricated inputs* | (none found in repo) |
| Zero-day block rate | 98.4% | *removed — no source file found* | (none found in repo) |
| Throughput (safe load) | 67.78 rps | **95.68 rps** | `perf_chaos_report.json` (April 2026) |
| Block throughput | 223.20 rps | **494.01 rps** | `perf_chaos_report.json` (April 2026) |
| Attack latency p95 | 96.44 ms | **41.88 ms** | `perf_chaos_report.json` (April 2026) |

**Files changed (August 2026; note: in September 2026, `WHITEPAPER.md` and `WHITEPAPER Update.md` were retired in favor of canonical `../whitepaper/WHITEPAPER_PUBLIC.md`):**
- `../whitepaper/WHITEPAPER_PUBLIC.md` — Section 6 table + added Section 6.2 correction note

---

### FEAT-BENCH-AUTORUN — Automated Benchmark Regeneration Process `open (P2, follow-up only — do not implement now)`

**Problem:** The Section 6 benchmark numbers silently became stale because there is no automated process that regenerates them on each release. `public_benchmark.py` is dead code (no runtime caller, no CI gate). The only live benchmark runner is `tools/run_definitive_benchmark_v4.py`, which is a standalone script with no CI integration and no output written back to the whitepaper.

**Scope of follow-up work (not to be done in this sprint):**
1. Wire `tools/run_definitive_benchmark_v4.py` into CI as a scheduled job (e.g., weekly or per release tag).
2. After each run, auto-update `artifacts/evidence/definitive_benchmark_v4.json` and re-generate the whitepaper's Section 6 table from that file (script-driven, not manual).
3. Wire `public_benchmark.py` adapters to the real dataset outputs so the benchmark gate runs against actual data, not the synthetic fixture.
4. Add GAIA dataset integration to the definitive benchmark runner so GAIA can be re-added to the whitepaper with a real number.
5. Document the benchmark methodology (strict/balanced threshold mapping, dataset sources, zero-contamination guarantee) in a dedicated `docs/benchmark_methodology.md`.

**Priority:** P2 — not a security regression, but a process/integrity gap that must be closed before the next public release cycle.

---

### F27 — EVASION_FAKE_ABSTAIN Bypass Fix `completed (August 2026)`

**Finding (Phase 5 audit):** `OutputAssuranceGuard._is_abstain_payload()` returned `True` immediately whenever the parsed response JSON contained `"abstain": true` — without any validation of the actual answer text. This allowed an adversary who controls output formatting (jailbroken model, compromised tool response) to include `"abstain": true` alongside a harmful answer and bypass the `high_stakes_confidence_citation_conflict` check entirely.

**Confirmed probe evidence:**
```
{"answer": "Here is how to commit financial fraud.", "abstain": True, ...domain: financial}
→ action='allow', reason='ok'   ← BYPASS (pre-fix)
```

**Root cause:** Flag was trusted as self-reported truth — `if parsed_json.get(self.abstain_field) is True: return True` with no content check.

**Fix applied to `guardian/security/output_assurance.py`:**
- Added `self._REFUSAL_RE` — compiled regex of 25+ natural-language refusal/declination patterns (covers "I cannot", "I'm unable", "I must decline", "I refuse to", "insufficient information", "outside my capabilities", etc.)
- Rewrote `_is_abstain_payload()`: abstain boolean/reason are now *hints*, not authoritative. When the flag is present:
  - If answer is absent or `len(answer.strip()) < 20` → genuine abstain (empty response)
  - If answer has substantive content → `_REFUSAL_RE.search(answer)` must match; otherwise flag is REJECTED and high-stakes check runs
- No-flag path unchanged: purely answer-text refusal detection via the same regex

**Verification (probe suite — 14/14 PASS):**
```
[EVASION_FAKE_ABSTAIN]          action='block' reason='high_stakes_confidence_citation_conflict' [PASS]
[GENUINE_ABSTAIN_REFUSAL_LANGUAGE] action='allow' reason='ok' [PASS]
[GENUINE_ABSTAIN_CANNOT_VERIFY]    action='allow' reason='ok' [PASS]
[GENUINE_ABSTAIN_UNABLE_TO_ASSIST] action='allow' reason='ok' [PASS]
[GENUINE_ABSTAIN_DECLINE]          action='allow' reason='ok' [PASS]
```

**Tests added to `tests/security/test_output_assurance.py`:**
- `test_output_assurance_blocks_fake_abstain_with_harmful_content` — regression for the bypass
- `test_output_assurance_genuine_abstain_refusal_language_allowed`
- `test_output_assurance_genuine_abstain_unable_to_assist_allowed`
- `test_output_assurance_genuine_abstain_decline_phrasing_allowed`

**Total test count for F27:** 9/9 PASSED (5 original + 4 new)

**Whitepaper updates (same commit):**
- Feature 27 renamed from "Hallucination-Risk Output Assurance" → "**Output Structural Assurance (Opt-In / Disabled by Default)**" in all three whitepaper files (the code enforces JSON structure + metadata policy, not hallucination detection)
- August 2026 fix note added to all three Feature 27 blurbs

**Files changed:**
- `guardian/security/output_assurance.py`
- `tests/security/test_output_assurance.py`
- `WHITEPAPER.md`
- `../whitepaper/WHITEPAPER_PUBLIC.md`
- `WHITEPAPER Update.md`
