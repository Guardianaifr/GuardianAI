import time
import logging
from collections import defaultdict
from typing import Dict, Tuple

"""
RateLimiter - IP-based Token Bucket Rate Limiting

This module provides a thread-safe (in-memory) implementation of the Token Bucket
algorithm to prevent brute-force attacks and resource abuse on the GuardianAI proxy.
"""
logger = logging.getLogger("GuardianAI.rate_limiter")

class RateLimiter:
    """
    Implements a Token Bucket rate limiter to control request flow per IP address.
    
    Attributes:
        capacity (int): The maximum number of tokens a bucket can hold (burst limit).
        refill_rate (float): The rate at which tokens are added to the bucket per second.
        buckets (dict): Internal storage mapping IP addresses to their current token count
                        and last refill timestamp.
    """
    def __init__(self, requests_per_minute: int = 60):
        """
        Initializes the RateLimiter with a specified requests-per-minute limit.

        Args:
            requests_per_minute (int): The maximum allowed requests per minute (default 60).
        """
        self.capacity = requests_per_minute  # Max burst
        self.refill_rate = requests_per_minute / 60.0  # Tokens per second
        
        # Dictionary to store (IP) -> (tokens, last_refill_time)
        self.buckets: Dict[str, Tuple[float, float]] = {}

    def is_allowed(self, ip: str) -> bool:
        """
        Determines if a request from the given IP address is allowed based on the
        token bucket state. Refills the bucket before checking.

        Args:
            ip (str): The requester's IP address.

        Returns:
            bool: True if allowed (token consumed), False if blocked (rate limit exceeded).
        """
        current_time = time.time()
        
        if ip not in self.buckets:
            self.buckets[ip] = (float(self.capacity), current_time)
            return True

        tokens, last_time = self.buckets[ip]
        
        # Refill tokens based on time elapsed
        elapsed = current_time - last_time
        new_tokens = tokens + (elapsed * self.refill_rate)
        tokens = min(float(self.capacity), new_tokens)
        
        if tokens >= 1.0:
            self.buckets[ip] = (tokens - 1.0, current_time)
            return True
        else:
            self.buckets[ip] = (tokens, current_time) # Update last_time even on failure to avoid "stuck" buckets
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
        if ip not in self.buckets:
            return 1.0
        tokens, _ = self.buckets[ip]
        return tokens / self.capacity
