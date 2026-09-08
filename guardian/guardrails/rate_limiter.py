import time
import logging
import json
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

"""
RateLimiter - Enterprise Token Bucket Rate Limiting (2026-Standard)
===================================================================
Feature #10-11: In-memory + Redis-backed distributed rate limiting
with full enterprise management APIs.

Key Capabilities:
    1. Token bucket algorithm (in-memory + Redis)
    2. Per-IP rate limiting with configurable RPM
    3. Redis-backed distributed mode with failover
    4. Per-IP/tenant custom limits
    5. IP whitelist (never throttled)
    6. IP ban list (always blocked)
    7. Sliding window burst detection
    8. Stats & metrics endpoint
    9. Blocked request audit log
   10. Runtime hot-config (change limits live)
   11. Export/import configuration
   12. Thread-safe concurrent access
   13. Tenant-aware multi-tenant support
   14. Automatic stale bucket cleanup

Author: GuardianAI Team
License: MIT
"""
logger = logging.getLogger("GuardianAI.rate_limiter")

_REDIS_RATE_LIMIT_LUA = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local offline_delta = tonumber(ARGV[4]) or 0

local data = redis.call("HMGET", key, "tokens", "last_time")
local tokens = tonumber(data[1])
local last_time = tonumber(data[2])

if not tokens then
    tokens = capacity
    last_time = now
else
    local elapsed = math.max(0, now - last_time)
    tokens = math.min(capacity, tokens + (elapsed * refill_rate))
end

if offline_delta > 0 then
    tokens = math.max(0, tokens - offline_delta)
end

if tokens >= 1.0 then
    tokens = tokens - 1.0
    redis.call("HMSET", key, "tokens", tokens, "last_time", now)
    redis.call("EXPIRE", key, 120)
    return 1
else
    redis.call("HMSET", key, "tokens", tokens, "last_time", now)
    redis.call("EXPIRE", key, 120)
    return 0
end
"""


class RateLimiter:
    """
    Implements a Token Bucket rate limiter to control request flow per IP address.
    Supports in-memory and Redis-backed modes with enterprise management APIs.

    Attributes:
        capacity (int): The maximum number of tokens a bucket can hold (burst limit).
        refill_rate (float): The rate at which tokens are added to the bucket per second.
        buckets (dict): Internal storage mapping IP addresses to their current token count
                        and last refill timestamp.
    """
    def __init__(
        self,
        requests_per_minute: int = 60,
        redis_client=None,
        redis_prefix: str = "guardian:ratelimit",
        time_fn=None,
    ):
        """
        Initializes the RateLimiter with a specified requests-per-minute limit.

        Args:
            requests_per_minute (int): The maximum allowed requests per minute (default 60).
            redis_client: Optional Redis client for distributed rate limiting.
            redis_prefix (str): Key prefix for Redis storage.
            time_fn: Optional time function for testing.
        """
        self.capacity = requests_per_minute  # Max burst
        self.refill_rate = requests_per_minute / 60.0  # Tokens per second
        self._time_fn = time_fn or time.time
        self.redis = redis_client
        self.redis_prefix = redis_prefix
        self.max_local_buckets = 50000

        # Dictionary to store (IP) -> (tokens, last_refill_time)
        self.buckets: Dict[str, Tuple[float, float]] = {}

        # ── Per-IP custom limits ─────────────────────────────────────
        self._custom_limits: Dict[str, int] = {}  # ip -> custom RPM

        # ── Whitelist & Banlist ──────────────────────────────────────
        self._whitelist: Set[str] = set()
        self._banlist: Set[str] = set()

        # ── Stats ────────────────────────────────────────────────────
        self._lock = threading.RLock()
        self._stats = {
            "total_requests": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "total_banned_blocked": 0,
            "total_whitelisted": 0,
            "unique_ips": 0,
        }
        self._blocked_log: List[Dict[str, Any]] = []

        # ── Sliding window burst detection ───────────────────────────
        self._burst_windows: Dict[str, List[float]] = {}  # ip -> timestamps
        self._burst_threshold: int = max(5, requests_per_minute // 6)  # per 10s
        self._burst_window_seconds: float = 10.0

        # ── Redis partition recovery ─────────────────────────────────
        # Tracks tokens consumed in-memory during Redis outages so they
        # can be lazily deducted from Redis when connectivity resumes.
        self._local_recovery_deltas: Dict[str, int] = {}  # ip -> tokens_consumed_offline

        self._redis_script = None
        if self.redis is not None:
            try:
                self._redis_script = self.redis.register_script(_REDIS_RATE_LIMIT_LUA)
            except Exception:
                self._redis_script = None

        # ── Background Janitor Daemon (ARCH-04 Fix) ───────────────────
        self._janitor_stop_event = threading.Event()
        self._janitor_thread = threading.Thread(
            target=self._run_janitor,
            daemon=True,
            name="RateLimiterJanitor",
        )
        self._janitor_thread.start()

    def _run_janitor(self):
        """Periodically sweeps stale IP buckets and trims memory (runs every 60s)."""
        while not self._janitor_stop_event.wait(60.0):
            try:
                self.cleanup_stale(max_age_seconds=300)
            except Exception as exc:
                logger.debug("RateLimiter janitor sweep encountered error: %s", exc)

    # ─── Core: Token Bucket ──────────────────────────────────────────────

    def is_allowed(self, ip: str) -> bool:
        """
        Determines if a request from the given IP address is allowed based on the
        token bucket state. Refills the bucket before checking.

        Args:
            ip (str): The requester's IP address.

        Returns:
            bool: True if allowed (token consumed), False if blocked (rate limit exceeded).
        """
        if not ip:
            ip = "unknown"

        with self._lock:
            self._stats["total_requests"] += 1

            # Banlist check (always deny)
            if ip in self._banlist:
                self._stats["total_blocked"] += 1
                self._stats["total_banned_blocked"] += 1
                self._log_blocked(ip, "banned")
                return False

            # Whitelist check (always allow)
            if ip in self._whitelist:
                self._stats["total_allowed"] += 1
                self._stats["total_whitelisted"] += 1
                return True

            # Track burst window
            self._track_burst(ip)

        # Redis path
        if self.redis is not None:
            try:
                result = self._is_allowed_redis(ip)
                with self._lock:
                    if result:
                        self._stats["total_allowed"] += 1
                    else:
                        self._stats["total_blocked"] += 1
                        self._log_blocked(ip, "rate_limited_redis")
                return result
            except Exception as e:
                logger.warning(f"Redis rate limiter failed, using in-memory fallback: {e}")
                # Fall through to in-memory path and track the delta for lazy sync

        # In-memory path
        with self._lock:
            current_time = self._time_fn()
            effective_capacity = self._get_effective_capacity(ip)
            effective_rate = effective_capacity / 60.0

            if ip not in self.buckets:
                self.buckets[ip] = (max(0.0, float(effective_capacity) - 1.0), current_time)
                self._stats["total_allowed"] += 1
                self._stats["unique_ips"] = len(self.buckets)
                if self.redis is not None:
                    self._local_recovery_deltas[ip] = self._local_recovery_deltas.get(ip, 0) + 1
                return True

            tokens, last_time = self.buckets[ip]

            # Refill tokens based on time elapsed
            elapsed = current_time - last_time
            new_tokens = tokens + (elapsed * effective_rate)
            tokens = min(float(effective_capacity), new_tokens)

            if tokens >= 1.0:
                self.buckets[ip] = (tokens - 1.0, current_time)
                self._stats["total_allowed"] += 1
                # If Redis was the intended backend (but failed), record this
                # token consumption as a delta to be lazily synced on recovery.
                if self.redis is not None:
                    self._local_recovery_deltas[ip] = self._local_recovery_deltas.get(ip, 0) + 1
                return True
            else:
                self.buckets[ip] = (tokens, current_time)
                self._stats["total_blocked"] += 1
                self._log_blocked(ip, "rate_limited")
                logger.warning(f"Rate limit exceeded for IP: {ip} (Bucket empty)")
                return False

    def get_pressure(self, ip: str) -> float:
        """
        Calculates the current "pressure" or capacity remaining for a specific IP.

        Args:
            ip (str): The requester's IP address.

        Returns:
            float: A value from 0.0 (empty) to 1.0 (full), representing bucket fullness.
        """
        if not ip:
            ip = "unknown"

        if self.redis is not None:
            try:
                return self._get_pressure_redis(ip)
            except Exception as e:
                logger.warning(f"Redis pressure read failed, using in-memory fallback: {e}")

        effective_capacity = self._get_effective_capacity(ip)
        if ip not in self.buckets:
            return 1.0
        tokens, _ = self.buckets[ip]
        return max(0.0, min(1.0, tokens / effective_capacity))

    # ─── Per-IP Custom Limits ────────────────────────────────────────────

    def set_custom_limit(self, ip: str, rpm: int) -> bool:
        """Set a custom requests-per-minute limit for a specific IP."""
        with self._lock:
            self._custom_limits[ip] = rpm
            logger.info(f"Set custom rate limit for {ip}: {rpm} RPM")
            return True

    def remove_custom_limit(self, ip: str) -> bool:
        """Remove a custom limit, reverting IP to default."""
        with self._lock:
            if ip in self._custom_limits:
                del self._custom_limits[ip]
                return True
            return False

    def _get_effective_capacity(self, ip: str) -> int:
        """Get the effective capacity for an IP (custom or default)."""
        return self._custom_limits.get(ip, self.capacity)

    # ─── Whitelist / Banlist ─────────────────────────────────────────────

    def add_whitelist(self, ip: str) -> bool:
        """Add an IP to the whitelist (never throttled)."""
        with self._lock:
            self._whitelist.add(ip)
            logger.info(f"Whitelisted IP: {ip}")
            return True

    def remove_whitelist(self, ip: str) -> bool:
        """Remove an IP from the whitelist."""
        with self._lock:
            if ip in self._whitelist:
                self._whitelist.discard(ip)
                return True
            return False

    def ban(self, ip: str) -> bool:
        """Permanently ban an IP (always blocked, regardless of tokens)."""
        with self._lock:
            self._banlist.add(ip)
            logger.info(f"Banned IP: {ip}")
            return True

    def unban(self, ip: str) -> bool:
        """Remove an IP from the ban list."""
        with self._lock:
            if ip in self._banlist:
                self._banlist.discard(ip)
                return True
            return False

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is banned."""
        return ip in self._banlist

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted."""
        return ip in self._whitelist

    # ─── Bucket Management ───────────────────────────────────────────────

    def reset(self, ip: str) -> bool:
        """Reset the token bucket for a specific IP."""
        with self._lock:
            if ip in self.buckets:
                del self.buckets[ip]
                return True
            return False

    def reset_all(self) -> int:
        """Reset all token buckets. Returns count of cleared buckets."""
        with self._lock:
            count = len(self.buckets)
            self.buckets.clear()
            return count

    def get_bucket_info(self, ip: str) -> Dict[str, Any]:
        """Get detailed info about a specific IP's bucket."""
        with self._lock:
            effective_capacity = self._get_effective_capacity(ip)
            if ip not in self.buckets:
                return {
                    "ip": ip,
                    "tokens": float(effective_capacity),
                    "capacity": effective_capacity,
                    "pressure": 1.0,
                    "is_banned": ip in self._banlist,
                    "is_whitelisted": ip in self._whitelist,
                    "custom_limit": self._custom_limits.get(ip),
                }
            tokens, last_time = self.buckets[ip]
            return {
                "ip": ip,
                "tokens": round(tokens, 2),
                "capacity": effective_capacity,
                "pressure": round(max(0.0, min(1.0, tokens / effective_capacity)), 3),
                "last_activity": last_time,
                "is_banned": ip in self._banlist,
                "is_whitelisted": ip in self._whitelist,
                "custom_limit": self._custom_limits.get(ip),
            }

    def get_all_buckets(self) -> List[Dict[str, Any]]:
        """Get info for all active buckets."""
        with self._lock:
            return [self.get_bucket_info(ip) for ip in list(self.buckets.keys())[:100]]

    def cleanup_stale(self, max_age_seconds: float = 300) -> int:
        """Remove stale buckets that haven't been accessed recently, prune burst windows, and enforce max capacity."""
        with self._lock:
            now = self._time_fn()
            stale = [ip for ip, (_, last) in self.buckets.items()
                     if now - last > max_age_seconds]
            for ip in stale:
                del self.buckets[ip]

            # Prune old timestamps in burst windows
            cutoff = now - self._burst_window_seconds
            empty_bursts = []
            for ip, timestamps in self._burst_windows.items():
                self._burst_windows[ip] = [t for t in timestamps if t > cutoff]
                if not self._burst_windows[ip]:
                    empty_bursts.append(ip)
            for ip in empty_bursts:
                del self._burst_windows[ip]

            # Enforce max_local_buckets ceiling (evict oldest accessed)
            if len(self.buckets) > self.max_local_buckets:
                excess = len(self.buckets) - self.max_local_buckets
                sorted_ips = sorted(self.buckets.items(), key=lambda item: item[1][1])
                for ip, _ in sorted_ips[:excess]:
                    del self.buckets[ip]

            self._stats["unique_ips"] = len(self.buckets)
            return len(stale)

    # ─── Burst Detection ────────────────────────────────────────────────

    def _track_burst(self, ip: str):
        """Track request timestamps for burst detection."""
        now = self._time_fn()
        if ip not in self._burst_windows:
            self._burst_windows[ip] = []
        window = self._burst_windows[ip]
        window.append(now)
        # Trim old entries
        cutoff = now - self._burst_window_seconds
        self._burst_windows[ip] = [t for t in window if t > cutoff]

    def is_bursting(self, ip: str) -> bool:
        """Check if an IP is currently sending requests in burst mode."""
        with self._lock:
            window = self._burst_windows.get(ip, [])
            now = self._time_fn()
            cutoff = now - self._burst_window_seconds
            recent = [t for t in window if t > cutoff]
            return len(recent) >= self._burst_threshold

    # ─── Audit Log ──────────────────────────────────────────────────────

    def _log_blocked(self, ip: str, reason: str):
        """Log a blocked request (called under lock)."""
        entry = {
            "ip": ip,
            "reason": reason,
            "timestamp": self._time_fn(),
        }
        self._blocked_log.append(entry)
        if len(self._blocked_log) > 500:
            self._blocked_log = self._blocked_log[-500:]

    def get_blocked_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent blocked request log entries."""
        with self._lock:
            return self._blocked_log[-limit:]

    # ─── Stats & Export ─────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return rate limiter statistics."""
        with self._lock:
            return {
                **self._stats,
                "default_rpm": self.capacity,
                "active_buckets": len(self.buckets),
                "custom_limits_count": len(self._custom_limits),
                "whitelist_count": len(self._whitelist),
                "banlist_count": len(self._banlist),
                "redis_enabled": self.redis is not None,
                "burst_threshold": self._burst_threshold,
            }

    def export_config(self) -> Dict[str, Any]:
        """Export current rate limiter configuration."""
        with self._lock:
            return {
                "default_rpm": self.capacity,
                "refill_rate": self.refill_rate,
                "custom_limits": dict(self._custom_limits),
                "whitelist": sorted(self._whitelist),
                "banlist": sorted(self._banlist),
                "burst_threshold": self._burst_threshold,
                "burst_window_seconds": self._burst_window_seconds,
                "redis_enabled": self.redis is not None,
                "redis_prefix": self.redis_prefix,
            }

    # ─── Redis Backend ──────────────────────────────────────────────────

    def _redis_key(self, ip: str) -> str:
        return f"{self.redis_prefix}:{ip}"

    def _read_redis_bucket(self, ip: str) -> Tuple[float, float]:
        key = self._redis_key(ip)
        try:
            hm_data = self.redis.hmget(key, "tokens", "last_time")
            if hm_data and hm_data[0] is not None:
                return float(hm_data[0]), float(hm_data[1] or self._time_fn())
        except Exception:
            pass
        raw = self.redis.get(key)
        if not raw:
            return float(self.capacity), self._time_fn()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        try:
            data = json.loads(raw)
            return float(data.get("tokens", self.capacity)), float(data.get("last_time", self._time_fn()))
        except Exception:
            return float(self.capacity), self._time_fn()

    def _write_redis_bucket(self, ip: str, tokens: float, last_time: float):
        key = self._redis_key(ip)
        try:
            self.redis.hmset(key, {"tokens": tokens, "last_time": last_time})
            self.redis.expire(key, 120)
        except Exception:
            payload = json.dumps({"tokens": tokens, "last_time": last_time})
            self.redis.setex(key, 120, payload)

    def _clear_offline_delta(self, ip: str, delta: int):
        if delta <= 0:
            return
        with self._lock:
            current = self._local_recovery_deltas.get(ip, 0)
            if current > delta:
                self._local_recovery_deltas[ip] = current - delta
            else:
                self._local_recovery_deltas.pop(ip, None)

    def _is_allowed_redis(self, ip: str) -> bool:
        current_time = self._time_fn()
        with self._lock:
            offline_delta = self._local_recovery_deltas.get(ip, 0)
        if offline_delta > 0:
            logger.info(
                f"[RateLimiter] Lazy sync for {ip}: deducted {offline_delta} offline token(s) "
                f"from Redis bucket on partition recovery."
            )

        effective_capacity = float(self._get_effective_capacity(ip))
        effective_refill = effective_capacity / 60.0
        key = self._redis_key(ip)

        # 1. Atomic execution via registered Lua script
        if self._redis_script is not None:
            try:
                res = self._redis_script(
                    keys=[key],
                    args=[effective_capacity, effective_refill, current_time, offline_delta],
                )
                self._clear_offline_delta(ip, offline_delta)
                allowed = bool(res == 1)
                if not allowed:
                    logger.warning(f"Rate limit exceeded for IP: {ip} (Bucket empty, redis)")
                return allowed
            except Exception as exc:
                logger.debug(f"Redis Lua script execution failed: {exc}")

        # 2. Direct eval fallback
        try:
            res = self.redis.eval(
                _REDIS_RATE_LIMIT_LUA,
                1,
                key,
                effective_capacity,
                effective_refill,
                current_time,
                offline_delta,
            )
            self._clear_offline_delta(ip, offline_delta)
            allowed = bool(res == 1)
            if not allowed:
                logger.warning(f"Rate limit exceeded for IP: {ip} (Bucket empty, redis)")
            return allowed
        except Exception as exc:
            logger.debug(f"Redis eval failed: {exc}, using read-modify-write fallback")

        # 3. Read-modify-write fallback if script execution not supported
        tokens, last_time = self._read_redis_bucket(ip)
        elapsed = current_time - last_time
        tokens = min(float(effective_capacity), tokens + (elapsed * effective_refill))

        if offline_delta > 0:
            tokens = max(0.0, tokens - float(offline_delta))

        if tokens >= 1.0:
            self._write_redis_bucket(ip, tokens - 1.0, current_time)
            self._clear_offline_delta(ip, offline_delta)
            return True
        self._write_redis_bucket(ip, tokens, current_time)
        self._clear_offline_delta(ip, offline_delta)
        logger.warning(f"Rate limit exceeded for IP: {ip} (Bucket empty, redis)")
        return False

    def _get_pressure_redis(self, ip: str) -> float:
        tokens, _ = self._read_redis_bucket(ip)
        return tokens / self.capacity
