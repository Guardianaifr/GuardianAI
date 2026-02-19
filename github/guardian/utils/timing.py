"""Timing instrumentation decorator for GuardianAI components."""
import time
import functools
import json
from pathlib import Path
from datetime import datetime

_timing_log = []

def timed(component_name: str):
    """Decorator that measures function execution time."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - start) * 1000
                _timing_log.append({
                    "component": component_name,
                    "function": func.__name__,
                    "latency_ms": round(elapsed_ms, 2),
                    "timestamp": datetime.now().isoformat(),
                    "status": "success",
                })
                return result
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                _timing_log.append({
                    "component": component_name,
                    "function": func.__name__,
                    "latency_ms": round(elapsed_ms, 2),
                    "timestamp": datetime.now().isoformat(),
                    "status": "error",
                    "error": str(e),
                })
                raise
        return wrapper
    return decorator

def get_timing_stats():
    """Get aggregated timing statistics."""
    if not _timing_log:
        return {"message": "No timing data collected"}
    from collections import defaultdict
    by_component = defaultdict(list)
    for entry in _timing_log:
        by_component[entry["component"]].append(entry["latency_ms"])
    stats = {}
    for comp, times in by_component.items():
        times.sort()
        n = len(times)
        stats[comp] = {
            "count": n,
            "p50": times[n//2] if n else 0,
            "p95": times[int(n*0.95)] if n else 0,
            "p99": times[int(n*0.99)] if n else 0,
            "mean": round(sum(times)/n, 2) if n else 0,
        }
    return stats