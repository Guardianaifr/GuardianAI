"""
UNSEEN DATA TEST - Feature #25 External IdP / JWT
===================================================
Real-world JWT attack patterns from jwt.io, PortSwigger JWT labs,
OWASP JWT cheat sheet, and CVE databases.
"""
import sys, os, time, base64, json, hashlib
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "guardian"))

from security.idp_revocation import (
    build_subject, _decode_jwt_claims, IdpRevocationClient,
    validate_jwt_claims, TokenBlacklist, OIDCDiscoveryCache,
    SessionBindingVerifier, MultiIdpFederation, RevocationSubject,
)

RESULTS = {}

def run_test(name, fn):
    try:
        fn()
        RESULTS[name] = "PASS"
        print(f"  [PASS] {name}")
    except Exception as e:
        RESULTS[name] = f"FAIL: {e}"
        print(f"  [FAIL] {name}: {e}")


def _make_jwt(claims: dict) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesig"


# ============ JWT CLAIM VALIDATION ============

def test_valid_claims():
    now = time.time()
    claims = {"sub": "user-1", "exp": now + 3600, "nbf": now - 10, "iss": "https://idp.example.com", "aud": "guardian-api"}
    ok, errors = validate_jwt_claims(claims, required_issuer="https://idp.example.com", required_audience="guardian-api")
    assert ok and not errors

def test_expired_token():
    claims = {"sub": "user-1", "exp": time.time() - 3600, "iss": "idp"}
    ok, errors = validate_jwt_claims(claims)
    assert not ok
    assert any("expired" in e.lower() for e in errors)

def test_not_yet_valid():
    claims = {"sub": "user-1", "exp": time.time() + 7200, "nbf": time.time() + 3600}
    ok, errors = validate_jwt_claims(claims)
    assert not ok
    assert any("not valid until" in e.lower() for e in errors)

def test_issuer_mismatch():
    claims = {"sub": "u", "exp": time.time() + 3600, "iss": "evil-issuer"}
    ok, errors = validate_jwt_claims(claims, required_issuer="trusted-idp")
    assert not ok
    assert any("issuer" in e.lower() for e in errors)

def test_audience_mismatch():
    claims = {"sub": "u", "exp": time.time() + 3600, "aud": "wrong-app"}
    ok, errors = validate_jwt_claims(claims, required_audience="guardian-api")
    assert not ok
    assert any("audience" in e.lower() for e in errors)

def test_audience_list():
    claims = {"sub": "u", "exp": time.time() + 3600, "aud": ["app-a", "guardian-api", "app-b"]}
    ok, _ = validate_jwt_claims(claims, required_audience="guardian-api")
    assert ok

def test_missing_exp():
    ok, errors = validate_jwt_claims({"sub": "u"})
    assert not ok
    assert any("missing exp" in e.lower() for e in errors)

def test_invalid_exp_type():
    ok, errors = validate_jwt_claims({"sub": "u", "exp": "not-a-number"})
    assert not ok
    assert any("invalid exp" in e.lower() for e in errors)


# ============ TOKEN BLACKLIST ============

def test_blacklist_revoke_and_check():
    bl = TokenBlacklist()
    h = hashlib.sha256(b"token123").hexdigest()
    assert not bl.is_revoked(h)
    bl.revoke(h)
    assert bl.is_revoked(h)
    assert bl.count() == 1

def test_blacklist_bounded():
    bl = TokenBlacklist()
    bl._MAX = 100
    for i in range(200):
        bl.revoke(f"hash_{i}")
    assert bl.count() <= 100


# ============ SESSION BINDING ============

def test_session_binding_ok():
    sb = SessionBindingVerifier()
    sb.bind("jti-1", "sess-A", client_ip="1.2.3.4")
    ok, msg = sb.verify("jti-1", "sess-A", client_ip="1.2.3.4")
    assert ok

def test_session_binding_hijack():
    sb = SessionBindingVerifier()
    sb.bind("jti-2", "sess-A", client_ip="1.2.3.4")
    ok, msg = sb.verify("jti-2", "sess-B", client_ip="5.6.7.8")
    assert not ok
    assert "session_mismatch" in msg

def test_session_binding_ip_change():
    sb = SessionBindingVerifier()
    sb.bind("jti-3", "sess-A", client_ip="10.0.0.1")
    ok, msg = sb.verify("jti-3", "sess-A", client_ip="99.99.99.99")
    assert not ok
    assert "ip_mismatch" in msg


# ============ OIDC DISCOVERY CACHE ============

def test_oidc_cache_set_get():
    cache = OIDCDiscoveryCache(ttl_seconds=60)
    doc = {"issuer": "https://idp.example.com", "jwks_uri": "https://idp.example.com/.well-known/jwks.json"}
    cache.set("https://idp.example.com", doc)
    assert cache.get("https://idp.example.com") == doc

def test_oidc_cache_ttl_expiry():
    cache = OIDCDiscoveryCache(ttl_seconds=60)
    cache._cache["https://old.idp"] = (time.time() - 120, {"old": True})
    assert cache.get("https://old.idp") is None

def test_oidc_cache_invalidate():
    cache = OIDCDiscoveryCache()
    cache.set("https://a.com", {"a": 1})
    cache.set("https://b.com", {"b": 2})
    cache.invalidate("https://a.com")
    assert cache.get("https://a.com") is None
    assert cache.get("https://b.com") is not None


# ============ MULTI-IDP FEDERATION ============

def test_multi_idp_register():
    fed = MultiIdpFederation()
    fed.register("okta", IdpRevocationClient({"enabled": False, "provider": "okta"}))
    fed.register("auth0", IdpRevocationClient({"enabled": False, "provider": "auth0"}))
    assert len(fed.list_providers()) == 2
    assert fed.get_provider("okta") is not None
    assert fed.get_provider("unknown") is None


# ============ JWT DECODE ADVERSARIAL ============

# Real attack JWTs from PortSwigger/jwt_tool
ADVERSARIAL_JWTS = [
    "",                                             # empty
    "not.a.jwt",                                    # garbage
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",        # alg:none
    "a.b.c.d.e",                                    # too many parts
    "eyJhbGciOiJIUzI1NiJ9..sig",                   # empty payload
    _make_jwt({"sub": "admin", "role": "superuser", "exp": time.time() + 99999}),  # forged claims
    _make_jwt({"sub": "'; DROP TABLE users;--"}),   # SQLi in sub
    _make_jwt({"sub": "<script>alert(1)</script>"}),# XSS in sub
    "A" * 10000,                                    # overflow
]

def test_jwt_decode_adversarial():
    for jwt_str in ADVERSARIAL_JWTS:
        claims = _decode_jwt_claims(jwt_str)
        assert isinstance(claims, dict), f"Should return dict for: {jwt_str[:30]}"

def test_build_subject_adversarial():
    for jwt_str in ADVERSARIAL_JWTS:
        subject = build_subject("sess-test", jwt_str)
        assert subject.session_id == "sess-test"
        # token_hash should always be set for non-empty tokens
        if jwt_str:
            assert subject.token_hash is not None


# ============ MAIN ============

def main():
    print("=" * 72)
    print("  UNSEEN DATA TEST - Feature #25 External IdP / JWT")
    print("  Sources: PortSwigger JWT labs, OWASP JWT cheat sheet, CVE DB")
    print("=" * 72)

    print("\n  [A] JWT Claim Validation")
    run_test("jwt_valid_claims", test_valid_claims)
    run_test("jwt_expired", test_expired_token)
    run_test("jwt_not_yet_valid", test_not_yet_valid)
    run_test("jwt_issuer_mismatch", test_issuer_mismatch)
    run_test("jwt_audience_mismatch", test_audience_mismatch)
    run_test("jwt_audience_list", test_audience_list)
    run_test("jwt_missing_exp", test_missing_exp)
    run_test("jwt_invalid_exp", test_invalid_exp_type)

    print("\n  [B] Token Blacklist")
    run_test("blacklist_basic", test_blacklist_revoke_and_check)
    run_test("blacklist_bounded", test_blacklist_bounded)

    print("\n  [C] Session Binding")
    run_test("binding_ok", test_session_binding_ok)
    run_test("binding_hijack", test_session_binding_hijack)
    run_test("binding_ip_change", test_session_binding_ip_change)

    print("\n  [D] OIDC Discovery Cache")
    run_test("oidc_cache", test_oidc_cache_set_get)
    run_test("oidc_ttl_expiry", test_oidc_cache_ttl_expiry)
    run_test("oidc_invalidate", test_oidc_cache_invalidate)

    print("\n  [E] Multi-IdP Federation")
    run_test("multi_idp", test_multi_idp_register)

    print("\n  [F] Adversarial JWT Decoding")
    run_test("jwt_decode_adversarial", test_jwt_decode_adversarial)
    run_test("jwt_subject_adversarial", test_build_subject_adversarial)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}
    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} unseen data tests passed")
    if failed:
        for k, v in failed.items():
            print(f"    {k}: {v}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
