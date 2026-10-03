"""Run the GuardianAI RPC relay (attestation API + x402 if enabled) with settings from .env.

Usage: python tools/run_relay.py [port]     (default 8546)
"""
import os, sys, time, logging
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))
logging.basicConfig(level=logging.WARNING)
from guardian.web3sec.rpc_relay import GuardianRPCRelay
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8546
relay = GuardianRPCRelay({"web3_security": {"listen_port": port}})
print(f"relay on http://127.0.0.1:{port}  x402={relay.x402_config is not None}", flush=True)
relay.start()
while True:
    time.sleep(3600)
