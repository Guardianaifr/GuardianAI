import pytest
from fastapi import HTTPException

import backend.main as backend_main


class _DummySocket:
    def __init__(self):
        self.timeout = None
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, data, target):
        self.sent.append((data, target))

    def close(self):
        self.closed = True


def test_syslog_sink_noop_when_not_configured(monkeypatch):
    called = {"value": False}

    def _fake_socket(*args, **kwargs):
        called["value"] = True
        return _DummySocket()

    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_HOST", "")
    monkeypatch.setattr(backend_main.socket, "socket", _fake_socket)
    result = backend_main._forward_syslog_audit_log({"action": "admin_action"})
    assert result is True
    assert called["value"] is False


def test_syslog_sink_sends_payload(monkeypatch):
    dummy = _DummySocket()

    def _fake_socket(*args, **kwargs):
        return dummy

    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_PORT", 5514)
    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_TIMEOUT_SEC", 2.5)
    monkeypatch.setattr(backend_main.socket, "socket", _fake_socket)

    result = backend_main._forward_syslog_audit_log({"action": "rotate_key"})
    assert result is True
    assert dummy.timeout == 2.5
    assert len(dummy.sent) == 1
    _, target = dummy.sent[0]
    assert target == ("127.0.0.1", 5514)
    assert dummy.closed is True


def test_syslog_sink_strict_failure_raises(monkeypatch):
    class _FailingSocket:
        def settimeout(self, timeout):
            return None

        def sendto(self, data, target):
            raise RuntimeError("syslog unreachable")

        def close(self):
            return None

    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setattr(backend_main.socket, "socket", lambda *args, **kwargs: _FailingSocket())

    with pytest.raises(HTTPException) as exc:
        backend_main._forward_syslog_audit_log({"action": "admin_action"}, strict=True)

    assert exc.value.status_code == 503
