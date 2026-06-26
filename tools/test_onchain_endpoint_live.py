"""
Live smoke test for /api/v1/contract/analyze/onchain.
Starts backend locally and validates Ethereum, BSC, and Monad flows.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List

import requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

BASE = "http://127.0.0.1:8001"
PASS = True


def check(label: str, ok: bool, detail: str = ""):
    global PASS
    icon = "[OK]" if ok else "[FAIL]"
    print(f"  {icon} {label}", f"-- {detail}" if detail else "")
    if not ok:
        PASS = False


def _call_onchain(payload: Dict[str, Any]) -> requests.Response:
    return requests.post(f"{BASE}/api/v1/contract/analyze/onchain", json=payload, timeout=90)


def _is_structured_error(resp: requests.Response) -> bool:
    try:
        body = resp.json()
    except Exception:
        return False
    return isinstance(body, dict) and isinstance(body.get("detail"), str)


def _validate_success_schema(resp: requests.Response) -> bool:
    try:
        body = resp.json()
    except Exception:
        return False
    needed = {"analysis_id", "chain", "language", "score", "grade", "vulnerabilities"}
    return isinstance(body, dict) and needed.issubset(set(body.keys()))


def main():
    print("=" * 68)
    print("  ON-CHAIN ENDPOINT LIVE SMOKE TEST (ETH / BSC / MONAD)")
    print("=" * 68)

    key_present = bool(os.getenv("GUARDIAN_ETHERSCAN_API_KEY", "").strip())
    print(f"\n[0] API key present via env: {key_present}")
    check("GUARDIAN_ETHERSCAN_API_KEY available", key_present)

    print("\n[1] Starting backend...")
    proc = subprocess.Popen(
        [sys.executable, "backend/main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={
            **os.environ,
            "GUARDIAN_BACKEND_PORT": "8001",
            "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        },
    )
    threading.Thread(target=lambda: [print(f"[SRV] {l.rstrip()}") for l in iter(proc.stdout.readline, "")], daemon=True).start()
    time.sleep(6)
    if proc.poll() is not None:
        print("[-] Backend failed to start")
        sys.exit(1)

    tests: List[Dict[str, str]] = [
        {
            "name": "Ethereum USDC",
            "chain": "ethereum",
            "contract_address": "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        },
        {
            "name": "BSC BUSD",
            "chain": "bsc",
            "contract_address": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
        },
        {
            "name": "Monad smoke",
            "chain": "monad",
            "contract_address": "0x0000000000008e6a39e03c7156e46b238c9e2036",
        },
    ]

    try:
        for idx, test in enumerate(tests, start=2):
            print(f"\n[{idx}] POST /api/v1/contract/analyze/onchain - {test['name']}")
            resp = _call_onchain({"chain": test["chain"], "contract_address": test["contract_address"]})
            check("HTTP response not 500", resp.status_code != 500, f"status={resp.status_code}")

            if resp.status_code == 200:
                check("Success payload schema", _validate_success_schema(resp))
                body = resp.json()
                print(
                    f"     chain={body.get('chain')} score={body.get('score')} "
                    f"grade={body.get('grade')} vulns={body.get('vulnerabilities_found')}"
                )
            elif resp.status_code == 400:
                check("Structured 400 error", _is_structured_error(resp))
                print(f"     detail={resp.json().get('detail')}")
            else:
                check("Expected 200 or 400", False, f"status={resp.status_code}")

    finally:
        print("\n[5] Stopping backend...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    print("\n" + "=" * 68)
    print(f"  {'ON-CHAIN ENDPOINT SMOKE PASSED' if PASS else 'ON-CHAIN ENDPOINT SMOKE FAILED'}")
    print("=" * 68)
    sys.exit(0 if PASS else 1)


if __name__ == "__main__":
    main()
