"""Offline tests for the x402 pay-per-approval gate (no network)."""
import json
import pytest
from flask import Flask

from guardian.payments import x402_gate
from guardian.payments.x402_gate import FreeTierCounter, install_x402_gate


def _app():
    app = Flask(__name__)

    @app.post("/api/v1/attest")
    def attest():
        return {"status": "approved"}

    @app.get("/health")
    def health():
        return {"ok": True}

    return app


def test_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("GUARDIAN_X402_ENABLED", raising=False)
    app = _app()
    assert install_x402_gate(app, str(tmp_path / "db.sqlite")) is None
    r = app.test_client().post("/api/v1/attest", json={"agent_id": "1"})
    assert r.status_code == 200


def test_enabled_requires_valid_pay_to(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_X402_ENABLED", "true")
    monkeypatch.setenv("GUARDIAN_X402_PAY_TO", "not-an-address")
    with pytest.raises(ValueError):
        install_x402_gate(_app(), str(tmp_path / "db.sqlite"))


def test_free_tier_counter_monthly_limit(tmp_path):
    c = FreeTierCounter(str(tmp_path / "db.sqlite"), 2)
    assert c.remaining("Agent-1") == 2
    c.consume("agent-1")
    assert c.remaining("AGENT-1") == 1
    c.consume("agent-1")
    assert c.remaining("agent-1") == 0
    assert c.remaining("agent-2") == 2


def test_free_tier_zero_means_always_pay(tmp_path):
    c = FreeTierCounter(str(tmp_path / "db.sqlite"), 0)
    assert c.remaining("agent-1") == 0


def test_free_tier_skips_payment_then_requires_it(monkeypatch, tmp_path):
    """With 1 free approval: first call passes without payment, second goes to the paywall."""
    monkeypatch.setenv("GUARDIAN_X402_ENABLED", "true")
    monkeypatch.setenv("GUARDIAN_X402_PAY_TO", "0x" + "11" * 20)
    monkeypatch.setenv("GUARDIAN_X402_FREE_PER_AGENT_MONTH", "1")
    import x402.http.middleware.flask as mw

    def fake_init(self, app, routes, server, *a, **k):
        def paywall(environ, start_response):
            start_response("402 Payment Required", [("Content-Type", "application/json")])
            return [b"{}"]
        app.wsgi_app = paywall
    monkeypatch.setattr(mw.PaymentMiddleware, "__init__", fake_init)

    app = _app()
    install_x402_gate(app, str(tmp_path / "db.sqlite"))
    client = app.test_client()
    r1 = client.post("/api/v1/attest", json={"agent_id": "7"})
    assert r1.status_code == 200 and r1.headers["X-Guardian-Billing"] == "free-tier"
    assert client.post("/api/v1/attest", json={"agent_id": "7"}).status_code == 402
    assert client.get("/health").status_code == 200  # other routes untouched
