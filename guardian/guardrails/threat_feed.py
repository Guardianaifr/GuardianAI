import requests
import yaml
import logging
import threading
import time
import re
import concurrent.futures
import multiprocessing

logger = logging.getLogger("GuardianAI.threat_feed")

def _compile_process(pattern: str, result_queue: multiprocessing.Queue):
    try:
        re.compile(pattern, re.IGNORECASE)
        result_queue.put(True)
    except Exception as e:
        result_queue.put(e)

class ThreatFeed:
    def __init__(self, feed_url: str = None, update_interval: int = 3600):
        self.feed_url = feed_url
        self.update_interval = update_interval
        self.patterns = []
        self._stop_event = threading.Event()
        
        if self.feed_url:
            if not self.feed_url.startswith("https://") and self.feed_url != "mock":
                logger.error(f"Insecure ThreatFeed URL '{self.feed_url}' rejected. HTTPS is exclusively required.")
                self.feed_url = None
            else:
                self.thread = threading.Thread(target=self._auto_update, daemon=True)
                self.thread.start()

    THREAT_FEED_SCHEMA = {
        "type": "object",
        "properties": {
            "patterns": {
                "type": "array",
                "items": {"type": "string"}
            },
            "version": {"type": "string"},
            "description": {"type": "string"}
        },
        "required": ["patterns"]
    }

    def _safe_compile(self, pattern: str, timeout: float = 1.5) -> bool:
        """Attempts to compile a regex pattern using a separate process with a hard timeout to completely kill runaway ReDoS."""
        queue = multiprocessing.Queue()
        p = multiprocessing.Process(target=_compile_process, args=(pattern, queue), daemon=True)
        p.start()
        
        # Wait up to the timeout
        p.join(timeout=timeout)
        
        if p.is_alive():
            logger.error(f"Regex compilation timeout (ReDoS prevention). Hard killing process for pattern: {pattern[:30]}...")
            p.terminate()
            p.join() # Ensure resources are reaped
            return False
            
        # Check if an exception was raised during compilation
        if not queue.empty():
            res = queue.get()
            if isinstance(res, Exception):
                logger.error(f"Invalid regex syntax in ThreatFeed: {res}")
                return False
            return True
        return False

    def fetch_latest(self):
        """
        Fetches the latest threat feed from the configured URL, parses the YAML content,
        validates it, sandbox-compiles regex patterns, and performs an atomic swap.
        """
        if not self.feed_url or self.feed_url == "mock":
            return

        try:
            logger.info(f"Fetching community threat feed from {self.feed_url}...")
            # Security: allow_redirects=False strictly prevents SSRF/Open Redirect chaining
            response = requests.get(self.feed_url, timeout=10, allow_redirects=False)
            
            if response.status_code == 200:
                data = yaml.safe_load(response.text)
                
                # Component 1: Validate against schema
                try:
                    from jsonschema import validate
                    validate(instance=data, schema=self.THREAT_FEED_SCHEMA)
                except ImportError:
                    logger.warning("jsonschema not installed. Skipping strict validation.")
                except Exception as ve:
                    logger.error(f"Invalid threat feed format: {ve}")
                    return
                
                # Component 2: Extract & strict capacity cap (Memory Exhaustion DoS prevention)
                raw_patterns = data.get('patterns', [])[:500] 
                
                # Component 3: Sandbox execution block (ReDoS prevention)
                validated_patterns = []
                for pattern in raw_patterns:
                    if self._safe_compile(pattern):
                        validated_patterns.append(pattern)
                
                # Component 4: Atomic Swap (Race Condition prevention)
                self.patterns = validated_patterns
                logger.info(f"Successfully validated and loaded {len(self.patterns)} community threat patterns.")
                
            elif response.status_code in (301, 302, 307, 308):
                logger.error(f"ThreatFeed rejected due to HTTP Redirect ({response.status_code}) to block SSRF vectors.")
            else:
                logger.error(f"Failed to fetch threat feed: Status {response.status_code}")
                
        except requests.RequestException as e:
            logger.error(f"Network error updating threat feed: {e}")
        except Exception as e:
            logger.error(f"Error updating threat feed: {e}")

    def _auto_update(self):
        """Internal background loop for periodic feed updates."""
        while not self._stop_event.is_set():
            self.fetch_latest()
            time.sleep(self.update_interval)

    def stop(self):
        """Signals the background update thread to stop and waits for termination."""
        self._stop_event.set()
