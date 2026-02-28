import pytest
import os
import time
from guardian.guardrails.rate_limiter import RateLimiter

@pytest.fixture
def redis_url():
    # Allow overriding via environment, default to local redis
    return os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/0")

def test_redis_rate_limiter_initialization(redis_url):
    """Test that RateLimiter initializes and connects to Redis."""
    rl = RateLimiter(requests_per_minute=60, redis_url=redis_url)
    
    # Try fetching the client explicitly
    client = rl._get_redis()
    
    # If standard CI/CD Redis isn't up, skip test. 
    # But for GitHub actions we expect it to be 100% up
    if not client:
        pytest.skip("Redis not found natively. Skipping strict Redis tests.")
        
    assert client.ping() is True

def test_redis_atomic_bucket_decrement(redis_url):
    """
    Test token bucket depletion using multiplexing burst patterns 
    against the atomic Redis Lua backend.
    """
    capacity = 10
    rl = RateLimiter(requests_per_minute=capacity, redis_url=redis_url)
    client = rl._get_redis()
    if not client:
        pytest.skip("Redis not found.")

    test_ip = "10.0.0.99"
    
    # Clean up the key first to ensure an empty bucket
    key = f"{rl.key_prefix}:{test_ip}"
    client.delete(key)

    allowed_count = 0
    # Send a burst of (capacity + 5) requests instantly 
    for _ in range(capacity + 5):
        if rl.is_allowed(test_ip):
            allowed_count += 1
            
    # Exactly 'capacity' tokens should have been allowed.
    # Because it is instantaneous, 0 tokens will organically refill.
    assert allowed_count == capacity, f"Expected {capacity} allowed requests, but got {allowed_count}"

    # Verify that it is rejecting effectively right now
    assert rl.is_allowed(test_ip) is False

def test_redis_memory_fallback():
    """Ensure it correctly degrades to memory if Redis simply isn't passed."""
    rl = RateLimiter(requests_per_minute=5, redis_url="")
    assert rl._get_redis() is None
    
    test_ip = "10.0.0.100"
    allowed_count = 0
    for _ in range(8):
        if rl.is_allowed(test_ip):
            allowed_count += 1
            
    assert allowed_count == 5
