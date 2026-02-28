import time
import logging
import secrets
from collections import defaultdict
from typing import Dict, Tuple, Any, Optional
import threading

"""
RateLimiter - IP-based Token Bucket Rate Limiting (Redis-backed)

This module provides an atomic, distributed implementation of the Token Bucket
algorithm using Redis Lua scripting to prevent true HTTP/2 multiplexing bursts
across multiple WSGI worker processes.
"""
logger = logging.getLogger("GuardianAI.rate_limiter")

_REDIS_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call("ZREMRANGEBYSCORE", key, 0, now - window_ms)
local count = redis.call("ZCARD", key)
if count >= limit then
    return 0
end
redis.call("ZADD", key, now, member)
redis.call("EXPIRE", key, math.ceil(window_ms / 1000) + 5)
return 1
"""

class RateLimiter:
    """
    Implements a Token Bucket rate limiter to control request flow per IP address.
    Uses Redis for atomic, cross-process synchrony to defeat HTTP/2 bursts.
    Falls back to an in-memory thread-safe lock if Redis is unavailable.
    """
    def __init__(self, requests_per_minute: int = 60, redis_url: str = ""):
        self.capacity = requests_per_minute  # Max burst
        self.refill_rate = requests_per_minute / 60.0  # Tokens per second
        self.redis_url = redis_url
        self.lock = threading.Lock()
        self.buckets: Dict[str, Tuple[float, float]] = {}
        
        # Redis State
        self._redis_client: Optional[Any] = None
        self._redis_script_sha: Optional[str] = None
        self._redis_init_attempted = False
        self._redis_fail_open = True
        self.key_prefix = "guardian:proxy:ratelimit"

    def _get_redis(self) -> Optional[Any]:
        if self._redis_init_attempted:
            return self._redis_client
        self._redis_init_attempted = True

        if not self.redis_url:
            return None

        try:
            import redis
            self._redis_client = redis.Redis.from_url(
                self.redis_url,
                socket_timeout=1.0,
                socket_connect_timeout=1.0,
                decode_responses=True,
            )
            self._redis_client.ping()
            self._redis_script_sha = self._redis_client.script_load(_REDIS_RATE_LIMIT_SCRIPT)
            return self._redis_client
        except Exception as exc:
            logger.warning(f"Failed to connect to Redis for rate limiting: {exc}. Falling back to in-memory.")
            self._redis_client = None
            return None

    def _check_redis(self, ip: str) -> bool:
        client = self._get_redis()
        if not client:
            return self._check_memory(ip)

        key = f"{self.key_prefix}:{ip}"
        now_ms = int(time.time() * 1000)
        member = f"{now_ms}:{secrets.token_hex(6)}"

        try:
            if self._redis_script_sha:
                allowed = int(client.evalsha(self._redis_script_sha, 1, key, now_ms, 60_000, self.capacity, member))
            else:
                allowed = int(client.eval(_REDIS_RATE_LIMIT_SCRIPT, 1, key, now_ms, 60_000, self.capacity, member))
                
            if allowed != 1:
                logger.warning(f"Rate limit exceeded for IP: {ip} (Redis limit hit)")
                return False
            return True
        except Exception as exc:
            logger.warning(f"Redis rate limiting failed: {exc}. Failing open (allowed).")
            return self._redis_fail_open

    def _check_memory(self, ip: str) -> bool:
        current_time = time.time()
        with self.lock:
            if ip not in self.buckets:
                self.buckets[ip] = (float(self.capacity - 1.0), current_time)
                return True

            tokens, last_time = self.buckets[ip]
            elapsed = current_time - last_time
            new_tokens = tokens + (elapsed * self.refill_rate)
            tokens = min(float(self.capacity), new_tokens)
            
            if tokens >= 1.0:
                self.buckets[ip] = (tokens - 1.0, current_time)
                return True
            else:
                self.buckets[ip] = (tokens, current_time)
                logger.warning(f"Rate limit exceeded for IP: {ip} (Memory bucket empty)")
                return False

    def is_allowed(self, ip: str) -> bool:
        """
        Determines if a request from the given IP address is allowed.
        Tries Redis first for WSGI-safety, falls back to memory.
        """
        if self.redis_url:
            return self._check_redis(ip)
        return self._check_memory(ip)

    def get_pressure(self, ip: str) -> float:
        """ Calculates memory bucket pressure. Redis pressure requires extra queries, so simulating for now. """
        if self.redis_url and self._get_redis():
            # Approximating pressure by query size if using Redis
            try:
                key = f"{self.key_prefix}:{ip}"
                client = self._get_redis()
                count = client.zcard(key)
                return count / self.capacity
            except Exception:
                return 0.0
        
        # Memory pressure
        if ip not in self.buckets:
            return 1.0
        tokens, _ = self.buckets[ip]
        return tokens / self.capacity
