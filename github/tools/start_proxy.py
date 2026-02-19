
import sys
import os
import logging

# Add guardian root to path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, "guardian"))

from guardian.runtime.interceptor import GuardianProxy

if __name__ == "__main__":
    test_config = {
        "guardian_id": "test-guardian",
        "proxy": {
            "listen_port": 8081,
            "target_url": "http://localhost:8080"
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 60
        },
        "security_policies": {
            "security_mode": "balanced"
        },
        "backend": {
            "enabled": False
        },
        "threat_feed": {
            "enabled": False
        }
    }
    
    logging.basicConfig(level=logging.INFO)
    print("Starting Guardian Proxy via wrapper...")
    proxy = GuardianProxy(test_config)
    proxy._run_server()
