# 2. FEAT-HONEY-PROFILE
if (Test-Path -Path guardian/guardrails/honeypot.py) {
    git add guardian/guardrails/honeypot.py
}
if (Test-Path -Path tests/unit/test_honeypot_profile.py) {
    git add tests/unit/test_honeypot_profile.py
}
git commit -m "FEAT-HONEY-PROFILE: Implemented AttackerProfiler and HoneypotAnalytics admin endpoints"

# 3. FEAT-TENANT-INMEM-HARDEN
git add guardian/security/tenant_isolation.py guardian/security/cost_abuse.py tests/security/test_tenant_isolation_concurrent.py
git commit -m "FEAT-TENANT-INMEM-HARDEN: Hardened in-memory tenant isolation against OOM and concurrent limits"

# 4. F18 red-probe rewrite
git add guardian/brain/red_probe.py 
if (Test-Path -Path tests/brain/test_red_probe.py) {
    git rm tests/brain/test_red_probe.py
}
git commit -m "Security Audit F18: Rewrote red-probe.py for proper testing and isolation"

# 8. F1/F3/F4/F6 Phase 1 fixes + Interceptor Wiring
git add guardian/guardrails/fast_path.py guardian/guardrails/encoding_detector.py guardian/guardrails/input_filter.py artifacts/threat_feeds/community_threat_feed_v1.yaml guardian/security/multimodal_guard.py guardian/runtime/interceptor.py guardian/main.py guardian/brain/purple_heal.py guardian/guardrails/ai_firewall.py
git commit -m "Security Audit Phase 1: Applied fixes for F1 FastPath blocklist, F3 De-obfuscation, F4 Persona Heuristics to ThreatFeed, F6 Multimodal steganography guard, and wired interceptor logic"

# Add remaining test files
git add tests/e2e/test_guardrail_advanced_e2e.py tests/e2e/test_guardrail_adversarial_chaos_e2e.py tests/e2e/test_f20_purple_hot_reload.py tests/runtime/test_interceptor.py tests/security/test_feedback_optimizations.py
git commit -m "Tests: Updated e2e and security test files for newly wired features"
