import datetime
import hmac
import math
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

class CredentialRotationPolicy:
    def __init__(self, ttl_seconds: int = 3600, cron_schedule: Optional[str] = None):
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.cron_schedule = cron_schedule
        self.credentials: Dict[str, Dict[str, Any]] = {}

    def issue_credential(self, agent_id: str, secret: str) -> None:
        self.credentials[str(agent_id)] = {
            "secret": str(secret),
            "issued_at": time.time(),
            "expires_at": time.time() + self.ttl_seconds
        }

    def is_valid(self, agent_id: str, secret: str) -> bool:
        cred = self.credentials.get(str(agent_id))
        if not cred:
            return False
        if not hmac.compare_digest(str(cred["secret"]), str(secret)):
            return False
        if time.time() > cred["expires_at"]:
            return False
        return True

    def rotate_credential(self, agent_id: str, new_secret: str) -> None:
        self.issue_credential(agent_id, new_secret)

    def trigger_cron_rotation(self, current_time: float) -> List[str]:
        # simplified mock for cron trigger based on TTL expiry
        rotated = []
        for agent_id, cred in list(self.credentials.items()):
            if current_time >= cred["expires_at"]:
                rotated.append(agent_id)
        return rotated


class AgentBehaviorAnomalyProfiler:
    def __init__(self, alpha: float = 0.3, threshold: float = 3.0):
        self.alpha = float(alpha)
        self.threshold = float(threshold)
        self.call_rates: Dict[str, float] = defaultdict(float)
        self.call_variances: Dict[str, float] = defaultdict(lambda: 1.0)
        self.endpoint_history: Dict[str, set] = defaultdict(set)
        self.last_call_time: Dict[str, float] = {}

    def log_api_call(self, agent_id: str, endpoint: str, timestamp: float) -> Dict[str, Any]:
        anomalies = []
        aid = str(agent_id)
        ep = str(endpoint)

        # Check for new endpoint
        if ep not in self.endpoint_history[aid]:
            if len(self.endpoint_history[aid]) > 0:
                anomalies.append(f"New unexpected endpoint accessed: {ep}")
            self.endpoint_history[aid].add(ep)

        # Timing and frequency
        if aid in self.last_call_time:
            time_diff = timestamp - self.last_call_time[aid]
            if time_diff < 0:
                anomalies.append(f"Out-of-order timestamp or clock skew: {time_diff:.4f}s")
            else:
                if time_diff == 0:
                    current_rate = 10000.0  # Burst / zero-delay call
                else:
                    current_rate = 1.0 / time_diff
                
                # EWMA update
                old_rate = self.call_rates[aid]
                new_rate = self.alpha * current_rate + (1 - self.alpha) * old_rate
                
                diff = current_rate - old_rate
                new_var = self.alpha * (diff ** 2) + (1 - self.alpha) * self.call_variances[aid]
                new_var = max(0.0, new_var)
                
                std_dev = math.sqrt(max(0.0, self.call_variances[aid]))
                
                if current_rate > old_rate + self.threshold * std_dev:
                    anomalies.append(f"Unusual call frequency spike: {current_rate:.2f} calls/sec")
                
                self.call_rates[aid] = new_rate
                self.call_variances[aid] = new_var
                self.last_call_time[aid] = timestamp
        else:
            self.call_rates[aid] = 1.0
            self.last_call_time[aid] = timestamp

        return {
            "is_anomalous": len(anomalies) > 0,
            "anomalies": anomalies
        }

