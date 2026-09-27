"""
SIEM Dead Letter Queue (DLQ) Replay Daemon

Periodically retries failed SIEM event deliveries with:
  - Exponential backoff (configurable base delay and multiplier)
  - Maximum retry count per event (after which events are logged FATAL and dropped)
  - Maximum queue size with oldest-event eviction
  - Delivery callback interface for pluggable SIEM backends
  - Event lifecycle tracking (attempts, last error, timestamps)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DLQEntry:
    """A failed SIEM event awaiting retry."""
    event: Dict[str, Any]
    target: str  # e.g. "splunk", "microsoft_siem", "elastic", "datadog"
    first_failure_ts: float = 0.0
    last_attempt_ts: float = 0.0
    attempt_count: int = 0
    last_error: str = ""
    next_retry_ts: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event": self.event,
            "target": self.target,
            "first_failure_ts": self.first_failure_ts,
            "last_attempt_ts": self.last_attempt_ts,
            "attempt_count": self.attempt_count,
            "last_error": self.last_error,
            "next_retry_ts": self.next_retry_ts,
        }


@dataclass
class ReplayResult:
    """Result of a DLQ replay cycle."""
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    dropped: int = 0  # permanently dropped after max retries
    remaining: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "dropped": self.dropped,
            "remaining": self.remaining,
        }


# Type alias for delivery callback
DeliveryCallback = Callable[[Dict[str, Any], str], bool]


class DLQReplayDaemon:
    """
    Dead Letter Queue replay daemon for failed SIEM deliveries.

    Events that fail delivery are placed in the DLQ. The daemon periodically
    retries delivery with exponential backoff. After max_retries, events
    are logged as FATAL and permanently dropped.

    Usage:
        daemon = DLQReplayDaemon(
            delivery_fn=my_siem_send,
            max_retries=5,
        )
        daemon.add_event(event, target="splunk", error="connection timeout")
        result = daemon.replay_cycle()
    """

    def __init__(
        self,
        *,
        delivery_fn: Optional[DeliveryCallback] = None,
        max_retries: int = 5,
        base_delay_seconds: float = 60.0,
        backoff_multiplier: float = 2.0,
        max_delay_seconds: float = 3600.0,
        max_queue_size: int = 10000,
    ):
        self.delivery_fn = delivery_fn or self._default_delivery
        self.max_retries = max_retries
        self.base_delay = base_delay_seconds
        self.backoff_multiplier = backoff_multiplier
        self.max_delay = max_delay_seconds
        self.max_queue_size = max_queue_size

        self._queue: List[DLQEntry] = []
        self._dropped_count: int = 0
        self._total_replayed: int = 0
        self._total_succeeded: int = 0

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "queue_size": self.queue_size,
            "total_dropped": self._dropped_count,
            "total_replayed": self._total_replayed,
            "total_succeeded": self._total_succeeded,
        }

    def add_event(
        self,
        event: Dict[str, Any],
        target: str,
        error: str = "",
        timestamp: Optional[float] = None,
    ) -> None:
        """Add a failed event to the DLQ."""
        ts = timestamp if timestamp is not None else time.time()

        entry = DLQEntry(
            event=event,
            target=target,
            first_failure_ts=ts,
            last_attempt_ts=ts,
            attempt_count=1,
            last_error=error,
            next_retry_ts=ts + self.base_delay,
        )

        self._queue.append(entry)

        # Evict oldest if queue is full
        if len(self._queue) > self.max_queue_size:
            evicted = self._queue.pop(0)
            self._dropped_count += 1
            logger.warning(
                "DLQ queue full — evicted oldest event for target '%s' "
                "(first failed at %s, %d attempts)",
                evicted.target,
                evicted.first_failure_ts,
                evicted.attempt_count,
            )

    def replay_cycle(self, current_time: Optional[float] = None) -> ReplayResult:
        """
        Run one replay cycle: retry all eligible events.

        Events are eligible if current_time >= next_retry_ts.
        """
        now = current_time if current_time is not None else time.time()
        result = ReplayResult()
        remaining: List[DLQEntry] = []

        for entry in self._queue:
            if now < entry.next_retry_ts:
                remaining.append(entry)
                continue

            result.attempted += 1
            self._total_replayed += 1

            try:
                success = self.delivery_fn(entry.event, entry.target)
            except Exception as exc:
                success = False
                entry.last_error = str(exc)

            if success:
                result.succeeded += 1
                self._total_succeeded += 1
                logger.info(
                    "DLQ replay succeeded for target '%s' after %d attempt(s)",
                    entry.target,
                    entry.attempt_count,
                )
            else:
                entry.attempt_count += 1
                entry.last_attempt_ts = now

                if entry.attempt_count > self.max_retries:
                    # Permanently drop
                    result.dropped += 1
                    self._dropped_count += 1
                    logger.error(
                        "FATAL: DLQ event permanently dropped for target '%s' "
                        "after %d retries. Last error: %s. Event: %s",
                        entry.target,
                        self.max_retries,
                        entry.last_error,
                        str(entry.event)[:200],
                    )
                else:
                    # Schedule next retry with exponential backoff
                    delay = min(
                        self.base_delay * (self.backoff_multiplier ** (entry.attempt_count - 1)),
                        self.max_delay,
                    )
                    entry.next_retry_ts = now + delay
                    result.failed += 1
                    remaining.append(entry)

        self._queue = remaining
        result.remaining = len(remaining)
        return result

    def get_queue_snapshot(self) -> List[Dict[str, Any]]:
        """Return a snapshot of the current DLQ."""
        return [e.to_dict() for e in self._queue]

    def clear(self) -> int:
        """Clear the DLQ and return the number of events dropped."""
        count = len(self._queue)
        self._queue.clear()
        self._dropped_count += count
        return count

    @staticmethod
    def _default_delivery(event: Dict[str, Any], target: str) -> bool:
        """Default no-op delivery function (always succeeds)."""
        return True
