"""
HEAVY UNSEEN DATA TEST — Feature #12 Auth / Tokenized Ingest
==============================================================
Tests all auth capabilities with hard unseen data:
  A. Bearer Token Telemetry Auth
  B. Service-to-Service Auth
  C. API Key CRUD (create/list/revoke/rotate)
  D. API Key Gated Telemetry
  E. Auth Token Endpoint + Rate Limiting
  F. Proxy Auth (JWT strip, header handling, model allowlist)
  G. Proxy Request Translation (multi-backend)
  H. Adversarial Auth Bypass Attempts
  I. Concurrent Auth Stress
"""
import sys, os, json, time, base64, threading, logging
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

logging.getLogger("guardian_backend").setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.WARNING)

RESULTS = {}
_test_counter = [0]

# Workspace-local scratch directory (avoids Windows temp lock issues)
SCRATCH_DIR = os.path.join(_root, "tools", "_auth_test_scratch")
os.makedirs(SCRATCH_DIR, exist_ok=True)

def run_test(name, fn):
    try:
        fn()
        RESULTS[name] = "PASS"
        print(f"  [PASS] {name}")
    except AssertionError as e:
        RESULTS[name] = f"FAIL: {e}"
        print(f"  [FAIL] {name}: {e}")
    except Exception as e:
        RESULTS[name] = f"ERROR: {type(e).__name__}: {e}"
        print(f"  [ERROR] {name}: {type(e).__name__}: {e}")


def _basic_auth(user="admin", pwd="guardian_default"):
    token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _get_backend_client(backend_token=None, service_token=None):
    """Load backend with a unique DB for isolated testing."""
    import importlib
    _test_counter[0] += 1
    db_path = os.path.join(SCRATCH_DIR, f"test_{_test_counter[0]}.db")
    # Clean stale
    if os.path.exists(db_path):
        try: os.remove(db_path)
        except: pass

    os.environ["GUARDIAN_ADMIN_USER"] = "admin"
    os.environ["GUARDIAN_ADMIN_PASS"] = "guardian_default"
    if backend_token:
        os.environ["GUARDIAN_BACKEND_TOKEN"] = backend_token
    else:
        os.environ.pop("GUARDIAN_BACKEND_TOKEN", None)
    if service_token:
        os.environ["GUARDIAN_SERVICE_AUTH_TOKEN"] = service_token
        os.environ["GUARDIAN_SERVICE_ID"] = "guardian-proxy"
    else:
        os.environ.pop("GUARDIAN_SERVICE_AUTH_TOKEN", None)
    os.environ.pop("GUARDIAN_SIEM_ENABLED", None)
    os.environ["GUARDIAN_TELEMETRY_REQUIRE_API_KEY"] = "false"

    sys.modules.pop("backend.main", None)
    mod = importlib.import_module("backend.main")
    mod = importlib.reload(mod)
    mod.DB_PATH = db_path
    mod.TELEMETRY_REQUIRE_API_KEY = False
    mod._rate_limit_state.clear()
    mod.init_db()
    from fastapi.testclient import TestClient
    return TestClient(mod.app), mod


# ═══════════════════════════════════════════════════════════════════════════
# A. BEARER TOKEN TELEMETRY AUTH
# ═══════════════════════════════════════════════════════════════════════════

def test_a1_bearer_token_required():
    client, mod = _get_backend_client(backend_token="secret-token-123")
    payload = {"guardian_id": "g1", "event_type": "injection", "severity": "HIGH", "details": {"path": "test"}, "timestamp": 0.0}
    r_no = client.post("/api/v1/telemetry", json=payload)
    assert r_no.status_code == 401, f"Expected 401, got {r_no.status_code}"
    r_bad = client.post("/api/v1/telemetry", json=payload, headers={"Authorization": "Bearer wrong"})
    assert r_bad.status_code == 401
    r_ok = client.post("/api/v1/telemetry", json=payload, headers={"Authorization": "Bearer secret-token-123"})
    assert r_ok.status_code == 200

def test_a2_no_token_open_access():
    client, mod = _get_backend_client(backend_token=None)
    payload = {"guardian_id": "g2", "event_type": "allowed_request", "severity": "LOW", "details": {"path": "test"}, "timestamp": 0.0}
    r = client.post("/api/v1/telemetry", json=payload)
    assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# B. SERVICE-TO-SERVICE AUTH
# ═══════════════════════════════════════════════════════════════════════════

def test_b1_service_auth_enforced():
    client, mod = _get_backend_client(backend_token="tok", service_token="svc-secret")
    payload = {"guardian_id": "g3", "event_type": "injection", "severity": "HIGH", "details": {}, "timestamp": 0.0}
    r_no_svc = client.post("/api/v1/telemetry", json=payload, headers={"Authorization": "Bearer tok"})
    assert r_no_svc.status_code == 401
    r_ok = client.post("/api/v1/telemetry", json=payload, headers={
        "Authorization": "Bearer tok",
        "X-Guardian-Service-Id": "guardian-proxy",
        "X-Guardian-Service-Token": "svc-secret",
    })
    assert r_ok.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# C. API KEY CRUD
# ═══════════════════════════════════════════════════════════════════════════

def test_c1_api_key_lifecycle():
    client, mod = _get_backend_client()
    # Create
    r = client.post("/api/v1/api-keys", json={"key_name": "test_key"}, headers=_basic_auth())
    assert r.status_code == 200
    data = r.json()
    assert data["key_name"] == "test_key"
    assert data["api_key"].startswith("gk_")
    assert data["is_active"] is True
    # List
    r2 = client.get("/api/v1/api-keys", headers=_basic_auth())
    assert r2.status_code == 200
    keys = r2.json()
    assert len(keys) >= 1
    key_id = keys[0]["id"]
    # Revoke
    r3 = client.post(f"/api/v1/api-keys/{key_id}/revoke", headers=_basic_auth())
    assert r3.status_code == 200
    assert r3.json()["is_active"] is False
    # Rotate
    r4 = client.post(f"/api/v1/api-keys/{key_id}/rotate", headers=_basic_auth())
    assert r4.status_code == 200
    assert r4.json()["is_active"] is True
    assert r4.json()["api_key"].startswith("gk_")

def test_c2_api_key_requires_auth():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/api-keys", json={"key_name": "unauthed"})
    assert r.status_code == 401

def test_c3_multiple_keys():
    client, mod = _get_backend_client()
    for i in range(5):
        r = client.post("/api/v1/api-keys", json={"key_name": f"key_{i}"}, headers=_basic_auth())
        assert r.status_code == 200
    r2 = client.get("/api/v1/api-keys", headers=_basic_auth())
    assert len(r2.json()) >= 5


# ═══════════════════════════════════════════════════════════════════════════
# D. API KEY GATED TELEMETRY
# ═══════════════════════════════════════════════════════════════════════════

def test_d1_api_key_telemetry_gate():
    client, mod = _get_backend_client()
    mod.TELEMETRY_REQUIRE_API_KEY = True
    # Create key
    cr = client.post("/api/v1/api-keys", json={"key_name": "gate_key"}, headers=_basic_auth())
    api_key = cr.json()["api_key"]
    payload = {"guardian_id": "g4", "event_type": "allowed_request", "severity": "LOW", "details": {}, "timestamp": 0.0}
    # No key = 401
    r_no = client.post("/api/v1/telemetry", json=payload)
    assert r_no.status_code == 401
    # Bad key = 401
    r_bad = client.post("/api/v1/telemetry", json=payload, headers={"x-api-key": "bad-key"})
    assert r_bad.status_code == 401
    # Good key = 200
    r_ok = client.post("/api/v1/telemetry", json=payload, headers={"x-api-key": api_key})
    assert r_ok.status_code == 200
    mod.TELEMETRY_REQUIRE_API_KEY = False  # Reset

def test_d2_revoked_key_rejected():
    client, mod = _get_backend_client()
    mod.TELEMETRY_REQUIRE_API_KEY = True
    cr = client.post("/api/v1/api-keys", json={"key_name": "revoke_me"}, headers=_basic_auth())
    api_key = cr.json()["api_key"]
    keys = client.get("/api/v1/api-keys", headers=_basic_auth()).json()
    key_id = keys[0]["id"]
    client.post(f"/api/v1/api-keys/{key_id}/revoke", headers=_basic_auth())
    payload = {"guardian_id": "g5", "event_type": "allowed_request", "severity": "LOW", "details": {}, "timestamp": 0.0}
    r = client.post("/api/v1/telemetry", json=payload, headers={"x-api-key": api_key})
    assert r.status_code == 401
    mod.TELEMETRY_REQUIRE_API_KEY = False


# ═══════════════════════════════════════════════════════════════════════════
# E. AUTH TOKEN ENDPOINT + RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════

def test_e1_auth_token_basic():
    client, mod = _get_backend_client()
    mod.AUTH_RATE_LIMIT_PER_MIN = 100
    r = client.post("/api/v1/auth/token", headers=_basic_auth())
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 3600

def test_e2_auth_token_bad_creds():
    client, mod = _get_backend_client()
    mod.AUTH_RATE_LIMIT_PER_MIN = 100
    r = client.post("/api/v1/auth/token", headers=_basic_auth("wrong", "wrong"))
    assert r.status_code == 401

def test_e3_auth_rate_limit():
    client, mod = _get_backend_client()
    mod.AUTH_RATE_LIMIT_PER_MIN = 2
    mod._rate_limit_state.clear()
    r1 = client.post("/api/v1/auth/token", headers=_basic_auth())
    assert r1.status_code == 200
    r2 = client.post("/api/v1/auth/token", headers=_basic_auth())
    assert r2.status_code == 200
    r3 = client.post("/api/v1/auth/token", headers=_basic_auth())
    assert r3.status_code == 429

def test_e4_rate_limit_per_ip():
    client, mod = _get_backend_client()
    mod.AUTH_RATE_LIMIT_PER_MIN = 1
    mod._rate_limit_state.clear()
    r1 = client.post("/api/v1/auth/token", headers={**_basic_auth(), "x-forwarded-for": "10.0.0.1"})
    assert r1.status_code == 200
    r2 = client.post("/api/v1/auth/token", headers={**_basic_auth(), "x-forwarded-for": "10.0.0.2"})
    assert r2.status_code == 200  # Different IP


# ═══════════════════════════════════════════════════════════════════════════
# F. PROXY AUTH (JWT strip, header handling, model allowlist)
# ═══════════════════════════════════════════════════════════════════════════

from guardian.proxy.auth_proxy import (
    ProxyConfig, translate_request, check_model_allowed,
    build_proxy_headers, TokenBucketRateLimiter, SUPPORTED_BACKENDS,
)

def test_f1_jwt_stripped_for_local():
    cfg = ProxyConfig(backend_type="ollama", strip_auth_header=True)
    headers = build_proxy_headers({"Authorization": "Bearer jwt_xxx", "Content-Type": "application/json"}, cfg)
    assert "Authorization" not in headers

def test_f2_jwt_kept_for_openai():
    cfg = ProxyConfig(backend_type="openai", strip_auth_header=True)
    headers = build_proxy_headers({"Authorization": "Bearer sk-xxx"}, cfg)
    assert "Authorization" in headers

def test_f3_model_allowlist_glob():
    assert check_model_allowed("llama3:70b-chat", ["llama*"]) is True
    assert check_model_allowed("gpt-4o", ["llama*"]) is False
    assert check_model_allowed("mistral:7b", ["llama*", "mistral*"]) is True

def test_f4_model_allowlist_empty():
    assert check_model_allowed("anything-goes", []) is True

def test_f5_hop_by_hop_stripped():
    cfg = ProxyConfig(backend_type="vllm")
    headers = build_proxy_headers({"Host": "evil.com", "Connection": "keep-alive", "X-Custom": "ok"}, cfg)
    assert "Host" not in headers
    assert "Connection" not in headers
    assert headers["X-Custom"] == "ok"

def test_f6_content_type_auto_added():
    cfg = ProxyConfig(backend_type="vllm")
    headers = build_proxy_headers({}, cfg)
    assert headers.get("Content-Type") == "application/json"


# ═══════════════════════════════════════════════════════════════════════════
# G. PROXY REQUEST TRANSLATION (MULTI-BACKEND)
# ═══════════════════════════════════════════════════════════════════════════

def test_g1_openai_to_ollama():
    cfg = ProxyConfig(backend_type="ollama")
    path, body = translate_request(
        "/v1/chat/completions",
        {"model": "llama3", "messages": [{"role": "user", "content": "test"}], "temperature": 0.5},
        cfg,
    )
    assert path == "/api/chat"
    assert body["model"] == "llama3"
    assert body["options"]["temperature"] == 0.5

def test_g2_vllm_passthrough():
    cfg = ProxyConfig(backend_type="vllm")
    path, body = translate_request(
        "/v1/chat/completions",
        {"model": "mistral", "messages": [{"role": "user", "content": "hello"}]},
        cfg,
    )
    assert path == "/v1/chat/completions"
    assert body["model"] == "mistral"

def test_g3_health_mapping():
    for backend_name in ["ollama", "vllm", "localai", "llamacpp"]:
        cfg = ProxyConfig(backend_type=backend_name)
        path, _ = translate_request("/health", {}, cfg)
        assert path == SUPPORTED_BACKENDS[backend_name].health_path

def test_g4_all_backends_have_required_paths():
    for name, b in SUPPORTED_BACKENDS.items():
        assert b.health_path, f"{name} missing health_path"
        assert b.chat_path, f"{name} missing chat_path"
        assert b.completions_path, f"{name} missing completions_path"

def test_g5_unknown_backend_defaults():
    cfg = ProxyConfig(backend_type="unknown_engine")
    assert cfg.backend.name == "OpenAI API"


# ═══════════════════════════════════════════════════════════════════════════
# H. ADVERSARIAL AUTH BYPASS ATTEMPTS
# ═══════════════════════════════════════════════════════════════════════════

def test_h1_sql_injection_in_token():
    client, mod = _get_backend_client(backend_token="real-token")
    payload = {"guardian_id": "g5", "event_type": "injection", "severity": "HIGH", "details": {}, "timestamp": 0.0}
    sqli_tokens = [
        "' OR '1'='1",
        "Bearer ' OR 1=1--",
        "Bearer \" UNION SELECT * FROM users--",
        "Bearer ${7*7}",
        "Bearer {{7*7}}",
    ]
    for token in sqli_tokens:
        r = client.post("/api/v1/telemetry", json=payload, headers={"Authorization": token})
        assert r.status_code == 401, f"SQLi bypass should be blocked: {token}"

def test_h2_null_byte_in_auth():
    client, mod = _get_backend_client(backend_token="real-token")
    payload = {"guardian_id": "g6", "event_type": "injection", "severity": "HIGH", "details": {}, "timestamp": 0.0}
    r = client.post("/api/v1/telemetry", json=payload, headers={"Authorization": "Bearer real-token\x00extra"})
    assert r.status_code == 401

def test_h3_empty_auth_header():
    client, mod = _get_backend_client(backend_token="real-token")
    payload = {"guardian_id": "g7", "event_type": "injection", "severity": "HIGH", "details": {}, "timestamp": 0.0}
    r = client.post("/api/v1/telemetry", json=payload, headers={"Authorization": ""})
    assert r.status_code == 401

def test_h4_basic_auth_wrong_creds():
    client, mod = _get_backend_client()
    r = client.get("/api/v1/events", auth=("admin", "wrong_password"))
    assert r.status_code == 401
    r2 = client.get("/api/v1/events", auth=("wrong_user", "guardian_default"))
    assert r2.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# I. CONCURRENT AUTH STRESS
# ═══════════════════════════════════════════════════════════════════════════

def test_i1_proxy_rate_limiter_concurrent():
    rl = TokenBucketRateLimiter(rpm=100)
    errors = []
    def hammer(user, n):
        try:
            for _ in range(n):
                rl.is_allowed(user)
        except Exception as e:
            errors.append(e)
    threads = [threading.Thread(target=hammer, args=(f"user_{i}", 20)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

def test_i2_model_allowlist_perf():
    patterns = [f"model_{i}*" for i in range(100)]
    start = time.perf_counter()
    for _ in range(10000):
        check_model_allowed("model_50:7b-chat", patterns)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      10K model checks: {elapsed:.1f}ms")
    assert elapsed < 1000


# ═══════════════════════════════════════════════════════════════════════════
# J. ADVANCED: SCOPED API KEYS + EXPIRY
# ═══════════════════════════════════════════════════════════════════════════

def test_j1_scoped_key_create():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/api-keys/advanced", json={"key_name": "scoped1", "scope": "telemetry"}, headers=_basic_auth())
    assert r.status_code == 200
    d = r.json()
    assert d["scope"] == "telemetry"
    assert d["api_key"].startswith("gk_tel_")
    assert d["is_active"] is True

def test_j2_scoped_key_events():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/api-keys/advanced", json={"key_name": "events1", "scope": "events"}, headers=_basic_auth())
    assert r.status_code == 200
    assert r.json()["api_key"].startswith("gk_eve_")

def test_j3_scoped_key_admin():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/api-keys/advanced", json={"key_name": "admin1", "scope": "admin"}, headers=_basic_auth())
    assert r.status_code == 200
    assert r.json()["api_key"].startswith("gk_adm_")

def test_j4_scoped_key_invalid_scope():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/api-keys/advanced", json={"key_name": "bad", "scope": "hacker"}, headers=_basic_auth())
    assert r.status_code == 400

def test_j5_scoped_key_with_ttl():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/api-keys/advanced", json={"key_name": "ttl1", "scope": "telemetry", "ttl_seconds": 3600}, headers=_basic_auth())
    assert r.status_code == 200
    d = r.json()
    assert d["ttl_seconds"] == 3600
    assert d["expires_at"] is not None
    assert d["expires_at"] > d["created_at"]

def test_j6_key_expiry_check():
    """Test _is_api_key_expired utility."""
    import importlib
    sys.modules.pop("backend.main", None)
    mod = importlib.import_module("backend.main")
    assert mod._is_api_key_expired(time.time(), ttl_sec=0) is False  # no expiry
    assert mod._is_api_key_expired(time.time() - 100, ttl_sec=50) is True  # expired
    assert mod._is_api_key_expired(time.time(), ttl_sec=3600) is False  # still valid


# ═══════════════════════════════════════════════════════════════════════════
# K. ADVANCED: FAILED AUTH LOCKOUT + AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════

def test_k1_failed_auth_tracking():
    """Record failures and check lockout triggers."""
    import importlib
    sys.modules.pop("backend.main", None)
    mod = importlib.import_module("backend.main")
    mod._failed_auth_tracker.clear()
    mod._lockout_tracker.clear()
    mod._auth_audit_log.clear()
    mod.AUTH_LOCKOUT_THRESHOLD = 3
    mod.AUTH_LOCKOUT_DURATION_SEC = 60
    for i in range(3):
        mod._record_failed_auth("10.99.99.1", "attacker")
    # Should be locked out now
    assert "10.99.99.1" in mod._lockout_tracker
    assert mod._lockout_tracker["10.99.99.1"] > time.time()

def test_k2_lockout_blocks():
    import importlib
    sys.modules.pop("backend.main", None)
    mod = importlib.import_module("backend.main")
    mod._lockout_tracker.clear()
    mod._lockout_tracker["10.99.99.2"] = time.time() + 60
    from fastapi import HTTPException
    blocked = False
    try:
        mod._check_lockout("10.99.99.2")
    except HTTPException as e:
        blocked = True
        assert e.status_code == 423
    assert blocked, "Lockout should block"

def test_k3_clear_failed_auth():
    import importlib
    sys.modules.pop("backend.main", None)
    mod = importlib.import_module("backend.main")
    mod._failed_auth_tracker["10.99.99.3"] = [time.time()]
    mod._lockout_tracker["10.99.99.3"] = time.time() + 60
    mod._clear_failed_auth("10.99.99.3")
    assert "10.99.99.3" not in mod._failed_auth_tracker
    assert "10.99.99.3" not in mod._lockout_tracker

def test_k4_auth_audit_log_bounded():
    import importlib
    sys.modules.pop("backend.main", None)
    mod = importlib.import_module("backend.main")
    mod._auth_audit_log.clear()
    for i in range(600):
        mod._record_auth_event("test", "127.0.0.1", "user", f"entry {i}")
    assert len(mod._auth_audit_log) <= mod._AUTH_AUDIT_MAX

def test_k5_audit_log_endpoint():
    client, mod = _get_backend_client()
    mod._auth_audit_log.clear()
    mod._record_auth_event("test_event", "1.2.3.4", "admin", "test detail")
    r = client.get("/api/v1/auth/audit-log?limit=10", headers=_basic_auth())
    assert r.status_code == 200
    d = r.json()
    assert d["total"] >= 1
    assert d["entries"][0]["event"] == "test_event"

def test_k6_lockout_status_endpoint():
    client, mod = _get_backend_client()
    mod._lockout_tracker.clear()
    mod._lockout_tracker["5.5.5.5"] = time.time() + 120
    r = client.get("/api/v1/auth/lockout-status", headers=_basic_auth())
    assert r.status_code == 200
    d = r.json()
    assert d["active_lockouts"] >= 1
    assert "5.5.5.5" in d["lockouts"]

def test_k7_manual_unlock():
    client, mod = _get_backend_client()
    mod._lockout_tracker["6.6.6.6"] = time.time() + 120
    mod._failed_auth_tracker["6.6.6.6"] = [time.time()]
    r = client.post("/api/v1/auth/lockout/6.6.6.6/unlock", headers=_basic_auth())
    assert r.status_code == 200
    assert r.json()["status"] == "unlocked"
    assert "6.6.6.6" not in mod._lockout_tracker


# ═══════════════════════════════════════════════════════════════════════════
# L. ADVANCED: TOKEN INTROSPECTION + AUTH STATS
# ═══════════════════════════════════════════════════════════════════════════

def test_l1_token_introspect_no_token():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/auth/token/introspect")
    assert r.status_code == 200
    assert r.json()["active"] is False

def test_l2_token_introspect_invalid():
    client, mod = _get_backend_client()
    r = client.post("/api/v1/auth/token/introspect", headers={"Authorization": "Bearer bogus-token"})
    assert r.status_code == 200
    assert r.json()["active"] is False

def test_l3_auth_stats():
    client, mod = _get_backend_client()
    mod._auth_audit_log.clear()
    mod._failed_auth_tracker.clear()
    mod._lockout_tracker.clear()
    r = client.get("/api/v1/auth/stats", headers=_basic_auth())
    assert r.status_code == 200
    d = r.json()
    assert "active_api_keys" in d
    assert "lockout_threshold" in d
    assert "admin_ip_allowlist_enabled" in d


# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("  HEAVY UNSEEN DATA TEST -- Feature #12 Auth / Tokenized Ingest")
    print("  (Base + 2026-Standard Advanced)")
    print("=" * 72)

    print("\n  [A] Bearer Token Telemetry Auth")
    run_test("bearer_required", test_a1_bearer_token_required)
    run_test("no_token_open", test_a2_no_token_open_access)

    print("\n  [B] Service-to-Service Auth")
    run_test("service_auth_enforced", test_b1_service_auth_enforced)

    print("\n  [C] API Key CRUD")
    run_test("api_key_lifecycle", test_c1_api_key_lifecycle)
    run_test("api_key_requires_auth", test_c2_api_key_requires_auth)
    run_test("multiple_keys", test_c3_multiple_keys)

    print("\n  [D] API Key Gated Telemetry")
    run_test("api_key_gate", test_d1_api_key_telemetry_gate)
    run_test("revoked_key_rejected", test_d2_revoked_key_rejected)

    print("\n  [E] Auth Token + Rate Limit")
    run_test("auth_token_basic", test_e1_auth_token_basic)
    run_test("auth_token_bad_creds", test_e2_auth_token_bad_creds)
    run_test("auth_rate_limit", test_e3_auth_rate_limit)
    run_test("rate_limit_per_ip", test_e4_rate_limit_per_ip)

    print("\n  [F] Proxy Auth")
    run_test("jwt_stripped_local", test_f1_jwt_stripped_for_local)
    run_test("jwt_kept_openai", test_f2_jwt_kept_for_openai)
    run_test("model_allowlist_glob", test_f3_model_allowlist_glob)
    run_test("model_allowlist_empty", test_f4_model_allowlist_empty)
    run_test("hop_by_hop_stripped", test_f5_hop_by_hop_stripped)
    run_test("content_type_auto", test_f6_content_type_auto_added)

    print("\n  [G] Proxy Request Translation")
    run_test("openai_to_ollama", test_g1_openai_to_ollama)
    run_test("vllm_passthrough", test_g2_vllm_passthrough)
    run_test("health_mapping", test_g3_health_mapping)
    run_test("all_backends_paths", test_g4_all_backends_have_required_paths)
    run_test("unknown_backend", test_g5_unknown_backend_defaults)

    print("\n  [H] Adversarial Auth Bypass")
    run_test("sqli_in_token", test_h1_sql_injection_in_token)
    run_test("null_byte_auth", test_h2_null_byte_in_auth)
    run_test("empty_auth", test_h3_empty_auth_header)
    run_test("wrong_basic_creds", test_h4_basic_auth_wrong_creds)

    print("\n  [I] Concurrent Stress")
    run_test("concurrent_rate_limiter", test_i1_proxy_rate_limiter_concurrent)
    run_test("model_check_perf", test_i2_model_allowlist_perf)

    print("\n  [J] Advanced: Scoped API Keys + Expiry")
    run_test("scoped_key_telemetry", test_j1_scoped_key_create)
    run_test("scoped_key_events", test_j2_scoped_key_events)
    run_test("scoped_key_admin", test_j3_scoped_key_admin)
    run_test("scoped_key_invalid", test_j4_scoped_key_invalid_scope)
    run_test("scoped_key_ttl", test_j5_scoped_key_with_ttl)
    run_test("key_expiry_check", test_j6_key_expiry_check)

    print("\n  [K] Advanced: Failed Auth Lockout + Audit Log")
    run_test("failed_auth_tracking", test_k1_failed_auth_tracking)
    run_test("lockout_blocks", test_k2_lockout_blocks)
    run_test("clear_failed_auth", test_k3_clear_failed_auth)
    run_test("audit_log_bounded", test_k4_auth_audit_log_bounded)
    run_test("audit_log_endpoint", test_k5_audit_log_endpoint)
    run_test("lockout_status", test_k6_lockout_status_endpoint)
    run_test("manual_unlock", test_k7_manual_unlock)

    print("\n  [L] Advanced: Token Introspection + Stats")
    run_test("introspect_no_token", test_l1_token_introspect_no_token)
    run_test("introspect_invalid", test_l2_token_introspect_invalid)
    run_test("auth_stats", test_l3_auth_stats)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}

    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    if failed:
        print(f"\n  FAILURES ({len(failed)}):")
        for k, v in failed.items(): print(f"    {k}: {v}")
    print(f"{'='*72}")

    out = os.path.join(_root, "artifacts", "evidence", "auth_heavy.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())

