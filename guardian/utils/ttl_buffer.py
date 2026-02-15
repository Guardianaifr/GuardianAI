"""Context Buffer TTL — expires entries after 5 minutes of inactivity."""
import time
import threading

class TTLBuffer:
    def __init__(self, ttl_seconds=300):
        self.ttl = ttl_seconds
        self._data = {}
        self._timestamps = {}
        self._lock = threading.Lock()
        self._start_cleanup()

    def set(self, key, value):
        with self._lock:
            self._data[key] = value
            self._timestamps[key] = time.time()

    def get(self, key):
        with self._lock:
            if key in self._data:
                if time.time() - self._timestamps[key] < self.ttl:
                    self._timestamps[key] = time.time()
                    return self._data[key]
                else:
                    del self._data[key]
                    del self._timestamps[key]
            return None

    def _cleanup(self):
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                expired = [k for k, t in self._timestamps.items() if now - t >= self.ttl]
                for k in expired:
                    del self._data[k]
                    del self._timestamps[k]

    def _start_cleanup(self):
        t = threading.Thread(target=self._cleanup, daemon=True)
        t.start()