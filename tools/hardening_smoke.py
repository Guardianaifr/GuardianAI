import argparse
import base64
import json
import sys
import time
from typing import Any, Dict, Tuple

import requests


def _basic_auth_header(username: str, password: str) -> Dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _request_json(
    method: str,
    url: str,
    expected_status: int,
    headers: Dict[str, str] | None = None,
    payload: Dict[str, Any] | None = None,
) -> Tuple[Dict[str, Any], int]:
    response = requests.request(method=method, url=url, headers=headers, json=payload, timeout=15)
    if response.status_code != expected_status:
        detail = response.text.strip()
        raise RuntimeError(
            f"{method} {url} failed: expected {expected_status}, got {response.status_code}. Body: {detail}"
        )
    if not response.text:
        return {}, response.status_code
    try:
        return response.json(), response.status_code
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"{method} {url} returned non-JSON body") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="GuardianAI backend hardening smoke test.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001", help="Backend base URL.")
    parser.add_argument("--admin-user", default="admin", help="Admin username.")
    parser.add_argument("--admin-pass", default="guardian_default", help="Admin password.")
    parser.add_argument("--guardian-id", default="smoke-guardian", help="Guardian ID used for test events.")
    parser.add_argument("--key-name", default="smoke_ingest_key", help="Managed API key name to create.")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    print(f"[1/7] Checking backend health at {base}/health")
    _request_json("GET", f"{base}/health", 200)

    print("[2/7] Issuing admin JWT token")
    token_payload, _ = _request_json(
        "POST",
        f"{base}/api/v1/auth/token",
        200,
        headers=_basic_auth_header(args.admin_user, args.admin_pass),
    )
    token = token_payload.get("access_token", "")
    if not token:
        raise RuntimeError("Token issuance response missing access_token")
    bearer_headers = {"Authorization": f"Bearer {token}"}

    print("[3/7] Creating managed telemetry API key")
    key_payload, _ = _request_json(
        "POST",
        f"{base}/api/v1/api-keys",
        200,
        headers={**bearer_headers, "Content-Type": "application/json"},
        payload={"key_name": f"{args.key_name}_{int(time.time())}"},
    )
    raw_key = key_payload.get("api_key", "")
    if not raw_key:
        raise RuntimeError("API key creation response missing api_key")

    print("[4/7] Posting admin_action telemetry event with API key")
    event_payload = {
        "guardian_id": args.guardian_id,
        "event_type": "admin_action",
        "severity": "high",
        "details": {"action": "smoke_test_action", "user": args.admin_user, "path": "/smoke"},
    }
    _request_json(
        "POST",
        f"{base}/api/v1/telemetry",
        200,
        headers={"x-api-key": raw_key, "Content-Type": "application/json"},
        payload=event_payload,
    )

    print("[5/7] Verifying tamper-evident audit chain")
    verify_payload, _ = _request_json("GET", f"{base}/api/v1/audit-log/verify", 200, headers=bearer_headers)
    if not verify_payload.get("ok", False):
        raise RuntimeError(f"audit-log verification failed: {json.dumps(verify_payload)}")

    print("[6/7] Reading queued audit delivery failures")
    failures_payload, _ = _request_json("GET", f"{base}/api/v1/audit-log/failures?limit=25", 200, headers=bearer_headers)
    if not isinstance(failures_payload, list):
        raise RuntimeError("Expected list payload from /api/v1/audit-log/failures")

    print("[7/7] Running retry endpoint for queued failures")
    retry_payload, _ = _request_json(
        "POST",
        f"{base}/api/v1/audit-log/retry-failures?limit=25",
        200,
        headers=bearer_headers,
    )
    for key in ("retried", "resolved", "failed"):
        if key not in retry_payload:
            raise RuntimeError(f"Retry response missing field: {key}")

    print("Hardening smoke PASSED")
    print(
        json.dumps(
            {
                "token_user": token_payload.get("user"),
                "token_role": token_payload.get("role"),
                "created_key_prefix": key_payload.get("key_prefix"),
                "audit_entries_checked": verify_payload.get("entries", 0),
                "failures_seen": len(failures_payload),
                "retry_result": retry_payload,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Hardening smoke FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
