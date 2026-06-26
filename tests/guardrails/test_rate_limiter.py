from guardrails.rate_limiter import RateLimiter


class FakeRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, _ttl, value):
        self.store[key] = value


class BrokenRedis:
    def get(self, _key):
        raise RuntimeError("redis unavailable")

    def setex(self, _key, _ttl, _value):
        raise RuntimeError("redis unavailable")


def test_in_memory_token_bucket_blocks_after_capacity():
    limiter = RateLimiter(requests_per_minute=2)
    assert limiter.is_allowed("1.2.3.4") is True
    assert limiter.is_allowed("1.2.3.4") is True
    assert limiter.is_allowed("1.2.3.4") is False


def test_token_bucket_refills_over_time():
    now = [1000.0]
    limiter = RateLimiter(requests_per_minute=60, time_fn=lambda: now[0])
    assert limiter.is_allowed("1.2.3.4") is True
    for _ in range(59):
        limiter.is_allowed("1.2.3.4")
    assert limiter.is_allowed("1.2.3.4") is False

    now[0] += 1.5  # ~1.5 tokens refilled
    assert limiter.is_allowed("1.2.3.4") is True


def test_per_ip_isolation():
    limiter = RateLimiter(requests_per_minute=1)
    assert limiter.is_allowed("10.0.0.1") is True
    assert limiter.is_allowed("10.0.0.1") is False
    assert limiter.is_allowed("10.0.0.2") is True


def test_redis_backend_token_bucket():
    now = [2000.0]
    redis = FakeRedis()
    limiter = RateLimiter(requests_per_minute=2, redis_client=redis, time_fn=lambda: now[0])

    assert limiter.is_allowed("9.9.9.9") is True
    assert limiter.is_allowed("9.9.9.9") is True
    assert limiter.is_allowed("9.9.9.9") is False
    assert limiter.get_pressure("9.9.9.9") < 0.5

    now[0] += 30.0  # refill one token with 2 rpm
    assert limiter.is_allowed("9.9.9.9") is True


def test_redis_failure_falls_back_to_memory():
    now = [3000.0]
    limiter = RateLimiter(requests_per_minute=1, redis_client=BrokenRedis(), time_fn=lambda: now[0])
    assert limiter.is_allowed("7.7.7.7") is True
    assert limiter.is_allowed("7.7.7.7") is False
