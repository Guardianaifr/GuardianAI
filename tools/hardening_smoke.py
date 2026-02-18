import argparse
import base64
import json
import sys
import time
from typing import Any, Dict, Iterable, Tuple

import requests


def _basic_auth_header(username: str, password: str) -> Dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _request_json(
    method: str,
    url: str,
    expected_status: int | Iterable[int],
    headers: Dict[str, str] | None = None,
    payload: Dict[str, Any] | None = None,
) -> Tuple[Dict[str, Any], int]:
    response = requests.request(method=method, url=url, headers=headers, json=payload, timeout=15)
    if isinstance(expected_status, int):
        expected_statuses = {expected_status}
    else:
        expected_statuses = {int(v) for v in expected_status}
    if response.status_code not in expected_statuses:
        detail = response.text.strip()
        raise RuntimeError(
            f"{method} {url} failed: expected {sorted(expected_statuses)}, got {response.status_code}. Body: {detail}"
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
    parser.add_argument("--auditor-user", default="", help="Optional auditor username for RBAC smoke checks.")
    parser.add_argument("--auditor-pass", default="", help="Optional auditor password for RBAC smoke checks.")
    parser.add_argument("--user-user", default="", help="Optional user username for RBAC smoke checks.")
    parser.add_argument("--user-pass", default="", help="Optional user password for RBAC smoke checks.")
    parser.add_argument("--guardian-id", default="smoke-guardian", help="Guardian ID used for test events.")
    parser.add_argument("--key-name", default="smoke_ingest_key", help="Managed API key name to create.")
    args = parser.parse_args()

    if bool(args.auditor_user) ^ bool(args.auditor_pass):
        raise RuntimeError("Both --auditor-user and --auditor-pass must be provided together.")
    if bool(args.user_user) ^ bool(args.user_pass):
        raise RuntimeError("Both --user-user and --user-pass must be provided together.")

    base = args.base_url.rstrip("/")
    print(f"[1/10] Checking backend health at {base}/health")
    _request_json("GET", f"{base}/health", 200)

    print("[2/10] Checking /metrics availability")
    metrics_response = requests.request(method="GET", url=f"{base}/metrics", timeout=15)
    if metrics_response.status_code not in {200, 404}:
        raise RuntimeError(
            f"GET {base}/metrics failed: expected [200, 404], got {metrics_response.status_code}. "
            f"Body: {metrics_response.text.strip()}"
        )
    if metrics_response.status_code == 200 and "guardian_" not in metrics_response.text:
        raise RuntimeError("Metrics endpoint returned 200 but did not include Guardian metrics payload.")

    print("[3/10] Issuing admin JWT token")
    token_payload, _ = _request_json(
        "POST",
        f"{base}/api/v1/auth/token",
        200,
        headers=_basic_auth_header(args.admin_user, args.admin_pass),
    )
    token = token_payload.get("access_token", "")
    if not token:
        raise RuntimeError("Token issuance response missing access_token")
    if token_payload.get("role") != "admin":
        raise RuntimeError(f"Expected admin token role, got: {token_payload.get('role')}")
    bearer_headers = {"Authorization": f"Bearer {token}"}

    print("[4/10] Creating managed telemetry API key")
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

    print("[5/10] Posting admin_action telemetry event with API key")
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

    print("[6/10] Verifying tamper-evident audit chain")
    verify_payload, _ = _request_json("GET", f"{base}/api/v1/audit-log/verify", 200, headers=bearer_headers)
    if not verify_payload.get("ok", False):
        raise RuntimeError(f"audit-log verification failed: {json.dumps(verify_payload)}")

    print("[7/10] Reading queued audit delivery failures")
    failures_payload, _ = _request_json("GET", f"{base}/api/v1/audit-log/failures?limit=25", 200, headers=bearer_headers)
    if not isinstance(failures_payload, list):
        raise RuntimeError("Expected list payload from /api/v1/audit-log/failures")

    print("[8/10] Running retry endpoint for queued failures")
    retry_payload, _ = _request_json(
        "POST",
        f"{base}/api/v1/audit-log/retry-failures?limit=25",
        200,
        headers=bearer_headers,
    )
    for key in ("retried", "resolved", "failed"):
        if key not in retry_payload:
            raise RuntimeError(f"Retry response missing field: {key}")

    if args.auditor_user and args.auditor_pass:
        print("[9/10] Running auditor RBAC smoke checks")
        auditor_token_payload, _ = _request_json(
            "POST",
            f"{base}/api/v1/auth/token",
            200,
            headers=_basic_auth_header(args.auditor_user, args.auditor_pass),
        )
        if auditor_token_payload.get("role") != "auditor":
            raise RuntimeError(f"Expected auditor token role, got: {auditor_token_payload.get('role')}")
        auditor_bearer = {"Authorization": f"Bearer {auditor_token_payload.get('access_token', '')}"}
        _request_json("GET", f"{base}/api/v1/audit-log/failures?limit=10", 200, headers=auditor_bearer)
        _request_json(
            "POST",
            f"{base}/api/v1/api-keys",
            403,
            headers={**auditor_bearer, "Content-Type": "application/json"},
            payload={"key_name": f"{args.key_name}_auditor_blocked_{int(time.time())}"},
        )
        _request_json("POST", f"{base}/api/v1/audit-log/retry-failures?limit=5", 403, headers=auditor_bearer)
        _request_json("POST", f"{base}/api/v1/auth/revoke", 200, headers=auditor_bearer)
    else:
        print("[9/10] Skipping auditor RBAC checks (no auditor credentials provided)")

    if args.user_user and args.user_pass:
        print("[10/10] Running user RBAC smoke checks")
        user_token_payload, _ = _request_json(
            "POST",
            f"{base}/api/v1/auth/token",
            200,
            headers=_basic_auth_header(args.user_user, args.user_pass),
        )
        if user_token_payload.get("role") != "user":
            raise RuntimeError(f"Expected user token role, got: {user_token_payload.get('role')}")
        user_bearer = {"Authorization": f"Bearer {user_token_payload.get('access_token', '')}"}
        _request_json("GET", f"{base}/api/v1/audit-log?limit=5", 403, headers=user_bearer)
        _request_json("GET", f"{base}/api/v1/events?limit=1", 200, headers=user_bearer)
        _request_json("POST", f"{base}/api/v1/auth/revoke", 200, headers=user_bearer)
    else:
        print("[10/10] Skipping user RBAC checks (no user credentials provided)")

    _request_json("POST", f"{base}/api/v1/auth/revoke", 200, headers=bearer_headers)

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
                "auditor_rbac_checked": bool(args.auditor_user and args.auditor_pass),
                "user_rbac_checked": bool(args.user_user and args.user_pass),
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
