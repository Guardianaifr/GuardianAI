import time
import hashlib
import hmac
import statistics
import pytest
from backend.auth import hash_password, verify_password, needs_rehash

def sha256_hash(password: str) -> str:
    import secrets
    salt = secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}${digest}"

class TestArgon2Benchmark:

    def test_argon2_hash_time_minimum(self):
        """Argon2 must take >= 100ms per hash (GPU resistance)"""
        password = "BenchmarkPassword123!"
        times = []
        for _ in range(5):
            start = time.perf_counter()
            hash_password(password)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_ms = statistics.mean(times) * 1000
        print(f"\nArgon2 average hash time: {avg_ms:.1f}ms")
        assert avg_ms >= 100, (
            f"Argon2 too fast ({avg_ms:.1f}ms) — "
            f"increase time_cost or memory_cost"
        )

    def test_sha256_hash_time_maximum(self):
        """SHA-256 should be < 1ms — confirms why we replaced it"""
        password = "BenchmarkPassword123!"
        times = []
        for _ in range(100):
            start = time.perf_counter()
            sha256_hash(password)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_ms = statistics.mean(times) * 1000
        print(f"\nSHA-256 average hash time: {avg_ms:.3f}ms")
        assert avg_ms < 1.0, (
            f"SHA-256 unexpectedly slow: {avg_ms:.3f}ms"
        )

    def test_speed_ratio(self):
        """Argon2 must be at least 1000x slower than SHA-256"""
        password = "BenchmarkPassword123!"
        
        start = time.perf_counter()
        for _ in range(10):
            sha256_hash(password)
        sha256_avg = (time.perf_counter() - start) / 10

        start = time.perf_counter()
        hash_password(password)
        argon2_time = time.perf_counter() - start

        ratio = argon2_time / sha256_avg
        print(f"\nSpeed ratio (Argon2/SHA-256): {ratio:.0f}x")
        assert ratio >= 1000, (
            f"Argon2 not slow enough vs SHA-256: only {ratio:.0f}x"
        )

    def test_backward_compat_migration_flow(self):
        """Full migration: SHA-256 hash → verify → rehash → verify new"""
        password = "MigrationTest456!"
        
        # Step 1: Create legacy SHA-256 hash
        legacy_hash = sha256_hash(password)
        assert needs_rehash(legacy_hash), \
            "Legacy hash should need rehash"

        # Step 2: Verify with legacy hash works
        assert verify_password(password, legacy_hash), \
            "Legacy verify should succeed"

        # Step 3: Rehash to Argon2
        new_hash = hash_password(password)
        assert not needs_rehash(new_hash), \
            "New Argon2 hash should not need rehash"

        # Step 4: Verify with new hash works
        assert verify_password(password, new_hash), \
            "New verify should succeed"

        # Step 5: Wrong password rejected
        assert not verify_password("wrongpassword", new_hash), \
            "Wrong password should fail"

    def test_wrong_password_rejected(self):
        """Argon2 must reject wrong passwords"""
        h = hash_password("correct-password")
        assert not verify_password("wrong-password", h)
        assert not verify_password("", h)
        assert not verify_password("correct-passwor", h)

    def test_unique_hashes(self):
        """Same password must produce different hashes (salt)"""
        password = "SamePassword789!"
        hashes = [hash_password(password) for _ in range(5)]
        assert len(set(hashes)) == 5, \
            "All hashes must be unique (salting not working)"
