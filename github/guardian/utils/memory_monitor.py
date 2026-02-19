"""Memory Monitor — alerts when usage exceeds threshold."""
import psutil, threading, logging
logger = logging.getLogger("guardian.memory")

class MemoryMonitor:
    def __init__(self, threshold_mb=500, interval_sec=30):
        self.threshold = threshold_mb
        self.interval = interval_sec
        self._running = False

    def start(self):
        self._running = True
        t = threading.Thread(target=self._monitor, daemon=True)
        t.start()

    def _monitor(self):
        while self._running:
            proc = psutil.Process()
            mem_mb = proc.memory_info().rss / 1024 / 1024
            if mem_mb > self.threshold:
                logger.warning(f"ALERT: Memory {mem_mb:.0f}MB exceeds {self.threshold}MB")
            import time; time.sleep(self.interval)

    def stop(self):
        self._running = False