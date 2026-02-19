import requests
import yaml
import logging
import threading
import time

logger = logging.getLogger("GuardianAI.threat_feed")

class ThreatFeed:
    def __init__(self, feed_url: str = None, update_interval: int = 3600):
        self.feed_url = feed_url
        self.update_interval = update_interval
        self.patterns = []
        self._stop_event = threading.Event()
        
        if self.feed_url:
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

    def fetch_latest(self):
        """
        Fetches the latest threat feed from the configured URL, parses the YAML content,
        and validates it against the internal JSON schema (if jsonschema is installed).
        """
        if not self.feed_url:
            return

        try:
            logger.info(f"Fetching community threat feed from {self.feed_url}...")
            response = requests.get(self.feed_url, timeout=10)
            if response.status_code == 200:
                data = yaml.safe_load(response.text)
                
                # Validate against schema
                try:
                    from jsonschema import validate
                    validate(instance=data, schema=self.THREAT_FEED_SCHEMA)
                    self.patterns = data.get('patterns', [])
                    logger.info(f"Successfully validated and loaded {len(self.patterns)} community threat patterns.")
                except ImportError:
                    logger.warning("jsonschema not installed. Skipping strict validation.")
                    self.patterns = data.get('patterns', [])
                except Exception as ve:
                    logger.error(f"Invalid threat feed format: {ve}")
            else:
                logger.error(f"Failed to fetch threat feed: Status {response.status_code}")
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
