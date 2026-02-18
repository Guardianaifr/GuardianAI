import json
import sys

import pytest

import tools.hardening_smoke as hardening_smoke


class _FakeResponse:
    def __init__(self, status_code, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        if text is not None:
            self.text = text
        elif payload is None:
            self.text = ""
        else:
            self.text = json.dumps(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("No JSON payload")
        return self._payload


def _install_request_mock(monkeypatch, expected_calls):
    def _fake_request(method, url, headers=None, json=None, timeout=15):
        assert timeout == 15
        assert expected_calls, f"Unexpected request: {method} {url}"
        expected = expected_calls.pop(0)
        assert method == expected["method"]
        assert url == expected["url"]
        if "check" in expected:
            result = expected["check"](headers or {}, json)
            assert result is not False
        return expected["response"]

    monkeypatch.setattr(hardening_smoke.requests, "request", _fake_request)


def test_hardening_smoke_main_success_without_optional_rbac(monkeypatch):
    base = "http://smoke.local"
    expected_calls = [
        {"method": "GET", "url": f"{base}/health", "response": _FakeResponse(200, {"status": "healthy"})},
        {"method": "GET", "url": f"{base}/metrics", "response": _FakeResponse(200, text="guardian_requests_total 2\n")},
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/token",
            "response": _FakeResponse(200, {"access_token": "admin-token", "user": "admin", "role": "admin"}),
        },
        {
            "method": "POST",
            "url": f"{base}/api/v1/api-keys",
            "check": lambda headers, payload: (
                headers["Authorization"] == "Bearer admin-token" and payload and "key_name" in payload
            ),
            "response": _FakeResponse(200, {"api_key": "gk_test", "key_prefix": "gk_test"}),
        },
        {"method": "POST", "url": f"{base}/api/v1/telemetry", "response": _FakeResponse(200, {"event_id": "e1"})},
        {"method": "GET", "url": f"{base}/api/v1/audit-log/verify", "response": _FakeResponse(200, {"ok": True, "entries": 1})},
        {"method": "GET", "url": f"{base}/api/v1/audit-log/failures?limit=25", "response": _FakeResponse(200, [])},
        {
            "method": "POST",
            "url": f"{base}/api/v1/audit-log/retry-failures?limit=25",
            "response": _FakeResponse(200, {"retried": 0, "resolved": 0, "failed": 0}),
        },
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/revoke",
            "response": _FakeResponse(200, {"status": "revoked", "revoked_jti": "id1", "revoked_by": "admin"}),
        },
    ]
    _install_request_mock(monkeypatch, expected_calls)
    monkeypatch.setattr(sys, "argv", ["hardening_smoke.py", "--base-url", base])

    rc = hardening_smoke.main()
    assert rc == 0
    assert not expected_calls


def test_hardening_smoke_main_success_with_optional_rbac(monkeypatch):
    base = "http://smoke.local"
    expected_calls = [
        {"method": "GET", "url": f"{base}/health", "response": _FakeResponse(200, {"status": "healthy"})},
        {"method": "GET", "url": f"{base}/metrics", "response": _FakeResponse(404, {"detail": "disabled"})},
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/token",
            "response": _FakeResponse(200, {"access_token": "admin-token", "user": "admin", "role": "admin"}),
        },
        {"method": "POST", "url": f"{base}/api/v1/api-keys", "response": _FakeResponse(200, {"api_key": "gk_test", "key_prefix": "gk_test"})},
        {"method": "POST", "url": f"{base}/api/v1/telemetry", "response": _FakeResponse(200, {"event_id": "e1"})},
        {"method": "GET", "url": f"{base}/api/v1/audit-log/verify", "response": _FakeResponse(200, {"ok": True, "entries": 2})},
        {"method": "GET", "url": f"{base}/api/v1/audit-log/failures?limit=25", "response": _FakeResponse(200, [])},
        {
            "method": "POST",
            "url": f"{base}/api/v1/audit-log/retry-failures?limit=25",
            "response": _FakeResponse(200, {"retried": 0, "resolved": 0, "failed": 0}),
        },
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/token",
            "response": _FakeResponse(200, {"access_token": "auditor-token", "user": "auditor", "role": "auditor"}),
        },
        {"method": "GET", "url": f"{base}/api/v1/audit-log/failures?limit=10", "response": _FakeResponse(200, [])},
        {"method": "POST", "url": f"{base}/api/v1/api-keys", "response": _FakeResponse(403, {"detail": "forbidden"})},
        {"method": "POST", "url": f"{base}/api/v1/audit-log/retry-failures?limit=5", "response": _FakeResponse(403, {"detail": "forbidden"})},
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/revoke",
            "response": _FakeResponse(200, {"status": "revoked", "revoked_jti": "id2", "revoked_by": "auditor"}),
        },
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/token",
            "response": _FakeResponse(200, {"access_token": "user-token", "user": "user1", "role": "user"}),
        },
        {"method": "GET", "url": f"{base}/api/v1/audit-log?limit=5", "response": _FakeResponse(403, {"detail": "forbidden"})},
        {"method": "GET", "url": f"{base}/api/v1/events?limit=1", "response": _FakeResponse(200, [])},
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/revoke",
            "response": _FakeResponse(200, {"status": "revoked", "revoked_jti": "id3", "revoked_by": "user1"}),
        },
        {
            "method": "POST",
            "url": f"{base}/api/v1/auth/revoke",
            "response": _FakeResponse(200, {"status": "revoked", "revoked_jti": "id4", "revoked_by": "admin"}),
        },
    ]
    _install_request_mock(monkeypatch, expected_calls)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hardening_smoke.py",
            "--base-url",
            base,
            "--auditor-user",
            "auditor",
            "--auditor-pass",
            "auditor-pass",
            "--user-user",
            "user1",
            "--user-pass",
            "user-pass",
        ],
    )

    rc = hardening_smoke.main()
    assert rc == 0
    assert not expected_calls


def test_hardening_smoke_requires_complete_optional_credential_pairs(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["hardening_smoke.py", "--auditor-user", "auditor-only"])
    with pytest.raises(RuntimeError, match="Both --auditor-user and --auditor-pass must be provided together."):
        hardening_smoke.main()
