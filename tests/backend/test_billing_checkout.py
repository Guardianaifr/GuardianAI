import importlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _load_backend(
    monkeypatch,
    tmp_path: Path,
    billing_mode: str = "mock",
    stripe_secret: str | None = None,
    stripe_price_starter: str | None = None,
    stripe_price_pro: str | None = None,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUARDIAN_ADMIN_USER", "admin")
    monkeypatch.setenv("GUARDIAN_ADMIN_PASS", "guardian_default")
    monkeypatch.delenv("GUARDIAN_BACKEND_TOKEN", raising=False)
    monkeypatch.delenv("GUARDIAN_SERVICE_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("GUARDIAN_BILLING_MODE", billing_mode)
    monkeypatch.setenv("GUARDIAN_PUBLIC_BASE_URL", "http://127.0.0.1:8001")
    if stripe_secret is None:
        monkeypatch.delenv("GUARDIAN_STRIPE_SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("GUARDIAN_STRIPE_SECRET_KEY", stripe_secret)
    if stripe_price_starter is None:
        monkeypatch.delenv("GUARDIAN_STRIPE_PRICE_STARTER", raising=False)
    else:
        monkeypatch.setenv("GUARDIAN_STRIPE_PRICE_STARTER", stripe_price_starter)
    if stripe_price_pro:
        monkeypatch.setenv("GUARDIAN_STRIPE_PRICE_PRO", stripe_price_pro)
    else:
        monkeypatch.delenv("GUARDIAN_STRIPE_PRICE_PRO", raising=False)
    monkeypatch.delenv("GUARDIAN_STRIPE_PRICE_ENTERPRISE", raising=False)
    monkeypatch.delenv("GUARDIAN_CRYPTO_API_KEY", raising=False)

    for k in list(sys.modules.keys()):
        if k.startswith("backend.routers.") or k == "backend.routers":
            sys.modules.pop(k, None)
    sys.modules.pop("backend.main", None)
    
    module = importlib.import_module("backend.main")
    reloaded = importlib.reload(module)
    
    import backend.routers.billing_routes as br
    br.BILLING_MODE = billing_mode
    if stripe_secret: br.STRIPE_SECRET_KEY = stripe_secret
    if stripe_price_starter: br.STRIPE_PRICE_STARTER = stripe_price_starter
    
    return reloaded


def test_public_site_and_plan_catalog(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, billing_mode="mock")
    client = TestClient(backend.app)

    site = client.get("/site")
    assert site.status_code == 200
    assert "GuardianAI" in site.text

    plans = client.get("/api/v1/public/plans")
    assert plans.status_code == 200
    body = plans.json()
    assert body["billing_mode"] == "mock"
    assert list(body["plans"].keys()) == ["free", "starter", "pro", "enterprise"]
    assert body["plans"]["pro"]["name"] == "Pro Gateway"
    assert body["plans"]["pro"]["amount_usd"] == 299
    assert "card" in body["payment_methods"]
    assert "crypto" in body["payment_methods"]


def test_mock_checkout_returns_redirect(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, billing_mode="mock")
    client = TestClient(backend.app)

    resp = client.post(
        "/api/v1/billing/checkout",
        json={"plan": "pro", "payment_method": "card"},
        auth=(backend.ADMIN_USER, backend.ADMIN_PASS)
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "mock"
    assert "/site/success" in body["checkout_url"]


def test_live_card_checkout_uses_stripe(monkeypatch, tmp_path):
    backend = _load_backend(
        monkeypatch,
        tmp_path,
        billing_mode="live",
        stripe_secret="sk_test_123",
        stripe_price_starter="price_123",
    )
    client = TestClient(backend.app)

    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return {"url": "https://checkout.stripe.com/c/session_123"}

    def _fake_post(url, headers=None, data=None, timeout=None):
        assert "stripe.com" in url
        assert headers["Authorization"] == "Bearer sk_test_123"
        assert data["line_items[0][price]"] == "price_123"
        assert data["mode"] == "payment"
        return _Resp()

    monkeypatch.setattr(backend.requests, "post", _fake_post)
    resp = client.post(
        "/api/v1/billing/checkout",
        json={"plan": "lifetime", "payment_method": "card"},
        auth=(backend.ADMIN_USER, backend.ADMIN_PASS)
    )
    assert resp.status_code == 200
    assert resp.json()["provider"] == "stripe"
    assert resp.json()["checkout_url"] == "https://checkout.stripe.com/c/session_123"

    import backend.routers.billing_routes
    print('TEST SEES BILLING_MODE=', backend.routers.billing_routes.BILLING_MODE)


def test_live_card_checkout_charges_chosen_plan(monkeypatch, tmp_path):
    """Pro must be charged the Pro price as a subscription, not the Starter price."""
    backend = _load_backend(
        monkeypatch,
        tmp_path,
        billing_mode="live",
        stripe_secret="sk_test_123",
        stripe_price_starter="price_starter",
        stripe_price_pro="price_pro",
    )
    client = TestClient(backend.app)
    seen = {}

    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return {"url": "https://checkout.stripe.com/c/session_pro"}

    def _fake_post(url, headers=None, data=None, timeout=None):
        seen.update(data)
        return _Resp()

    monkeypatch.setattr(backend.requests, "post", _fake_post)
    resp = client.post(
        "/api/v1/billing/checkout",
        json={"plan": "pro", "payment_method": "card"},
        auth=(backend.ADMIN_USER, backend.ADMIN_PASS),
    )
    assert resp.status_code == 200
    assert seen["line_items[0][price]"] == "price_pro"
    assert seen["mode"] == "subscription"
