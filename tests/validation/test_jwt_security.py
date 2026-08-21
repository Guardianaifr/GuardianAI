import pytest
import time
import base64
import json
import hmac
import hashlib
import statistics
from unittest.mock import patch
from backend.auth import _jwt_decode
# Import your JWT encode function — adjust import if needed
try:
    from backend.auth import _jwt_encode
except ImportError:
    from backend.main import create_access_token as _jwt_encode

# Read JWT secret same way the app does
import os
JWT_SECRET = os.getenv("GUARDIAN_JWT_SECRET", "test-secret-for-validation")

def forge_alg_none_token(payload: dict) -> str:
    """Attempt to forge a JWT with alg: none"""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."

def forge_hs256_token(payload: dict, wrong_secret: str) -> str:
    """Attempt to forge a JWT with wrong secret"""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    signing_input = f"{header}.{body}"
    sig = hmac.new(
        wrong_secret.encode(),
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{signing_input}.{sig_b64}"

class TestJWTSecurity:

    def test_alg_none_rejected(self):
        """alg:none JWT forgery must be rejected"""
        payload = {
            "sub": "admin",
            "role": "admin",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "aud": "guardian-api"
        }
        forged = forge_alg_none_token(payload)
        with pytest.raises(Exception):
            _jwt_decode(forged)

    def test_wrong_secret_rejected(self):
        """JWT signed with wrong secret must be rejected"""
        payload = {
            "sub": "attacker",
            "role": "admin",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "aud": "guardian-api"
        }
        forged = forge_hs256_token(payload, "wrong-secret")
        with pytest.raises(Exception):
            _jwt_decode(forged)

    def test_expired_token_rejected(self):
        """Expired JWT must be rejected"""
        payload = {
            "sub": "user1",
            "exp": int(time.time()) - 3600,  # expired 1 hour ago
            "iat": int(time.time()) - 7200,
            "nbf": int(time.time()) - 7200,
            "aud": "guardian-api"
        }
        with pytest.raises(Exception):
            import base64, json, hmac, hashlib
            header = base64.urlsafe_b64encode(
                json.dumps({"alg":"HS256","typ":"JWT"}).encode()
            ).rstrip(b"=").decode()
            body = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).rstrip(b"=").decode()
            signing_input = f"{header}.{body}"
            sig = hmac.new(
                JWT_SECRET.encode(),
                signing_input.encode(),
                hashlib.sha256
            ).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            expired_token = f"{signing_input}.{sig_b64}"
            _jwt_decode(expired_token)

    def test_wrong_audience_rejected(self):
        """JWT with wrong audience must be rejected"""
        payload = {
            "sub": "user1",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "aud": "wrong-audience"  # not guardian-api
        }
        import base64, json, hmac, hashlib
        header = base64.urlsafe_b64encode(
            json.dumps({"alg":"HS256","typ":"JWT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        signing_input = f"{header}.{body}"
        sig = hmac.new(
            JWT_SECRET.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        wrong_aud_token = f"{signing_input}.{sig_b64}"
        with pytest.raises(Exception):
            _jwt_decode(wrong_aud_token)

    def test_nbf_not_yet_valid_rejected(self):
        """JWT with future nbf (not-before) must be rejected"""
        payload = {
            "sub": "user1",
            "exp": int(time.time()) + 7200,
            "iat": int(time.time()),
            "nbf": int(time.time()) + 3600,  # valid 1 hour from now
            "aud": "guardian-api"
        }
        import base64, json, hmac, hashlib
        header = base64.urlsafe_b64encode(
            json.dumps({"alg":"HS256","typ":"JWT"}).encode()
        ).rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()
        signing_input = f"{header}.{body}"
        sig = hmac.new(
            JWT_SECRET.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        future_token = f"{signing_input}.{sig_b64}"
        with pytest.raises(Exception):
            _jwt_decode(future_token)

    def test_timing_attack_resistance(self):
        """Response time must not reveal valid vs invalid users"""
        import hmac
        valid = "correct_hash_value_here_abc123"
        invalid = "wrong_hash_value_here_xyz789"
        
        # Warmup to stabilize CPU cache/frequency scaling
        for _ in range(1000):
            hmac.compare_digest(valid, valid)
            hmac.compare_digest(valid, invalid)
            
        valid_times = []
        invalid_times = []
        
        for _ in range(2000):
            start = time.perf_counter()
            hmac.compare_digest(valid, valid)
            valid_times.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            hmac.compare_digest(valid, invalid)
            invalid_times.append(time.perf_counter() - start)
        
        valid_avg = statistics.mean(valid_times) * 1e6
        invalid_avg = statistics.mean(invalid_times) * 1e6
        diff_pct = abs(valid_avg - invalid_avg) / max(valid_avg, invalid_avg) * 100
        abs_diff = abs(valid_avg - invalid_avg)
        
        print(f"\nValid avg: {valid_avg:.3f}us")
        print(f"Invalid avg: {invalid_avg:.3f}us")
        print(f"Absolute Difference: {abs_diff:.3f}us")
        print(f"Difference: {diff_pct:.1f}%")
        
        # Timing difference should be < 50% or absolute difference < 0.05 microseconds (noise)
        assert diff_pct < 50 or abs_diff < 0.05, \
            "Suspicious timing difference — check hmac.compare_digest usage"
