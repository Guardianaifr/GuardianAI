import importlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _load_backend(monkeypatch, tmp_path: Path, billing_mode: str = "mock"):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUARDIAN_ADMIN_USER", "admin")
    monkeypatch.setenv("GUARDIAN_ADMIN_PASS", "guardian_default")
    monkeypatch.setenv("GUARDIAN_BILLING_MODE", billing_mode)
    monkeypatch.setenv("GUARDIAN_PUBLIC_BASE_URL", "http://127.0.0.1:8001")
    monkeypatch.delenv("GUARDIAN_BACKEND_TOKEN", raising=False)
    monkeypatch.delenv("GUARDIAN_SERVICE_AUTH_TOKEN", raising=False)
    sys.modules.pop("backend.main", None)
    module = importlib.import_module("backend.main")
    return importlib.reload(module)


def test_checkout_persists_order_and_customer(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, billing_mode="mock")
    client = TestClient(backend.app)

    r = client.post(
        "/api/v1/billing/checkout",
        json={
            "plan": "lifetime",
            "payment_method": "card",
            "customer_email": "owner@example.com",
            "tenant_name": "acme",
        },
        auth=("admin", "guardian_default")
    )
    assert r.status_code == 200
    order_id = r.json()["order_id"]

    orders = client.get("/api/v1/orders", auth=("admin", "guardian_default"))
    assert orders.status_code == 200
    assert any(o["order_id"] == order_id for o in orders.json())

    customers = client.get("/api/v1/customers", auth=("admin", "guardian_default"))
    assert customers.status_code == 200
    assert any(c["email"] == "owner@example.com" for c in customers.json())


def test_confirm_and_issue_license_flow(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, billing_mode="mock")
    client = TestClient(backend.app)

    checkout = client.post(
        "/api/v1/billing/checkout",
        json={"plan": "lifetime", "payment_method": "crypto", "customer_email": "buyer@example.com"},
        auth=("admin", "guardian_default")
    )
    assert checkout.status_code == 200
    order_id = checkout.json()["order_id"]

    confirm = client.post(
        "/api/v1/billing/confirm",
        auth=("admin", "guardian_default"),
        json={
            "order_id": order_id,
            "provider_transaction_id": "tx_123",
            "provider_status": "confirmed",
            "machine_id": "abcd1234abcd9999",
        },
    )
    assert confirm.status_code == 200
    assert confirm.json()["status"] == "paid"

    issue = client.post(
        "/api/v1/licenses/issue",
        auth=("admin", "guardian_default"),
        json={"order_id": order_id, "machine_id": "abcd1234abcd9999"},
    )
    assert issue.status_code == 200
    payload = issue.json()
    assert payload["status"] == "issued"
    assert payload["license_key"].startswith("GAI-abcd1234abcd-")

    licenses = client.get("/api/v1/licenses", auth=("admin", "guardian_default"))
    assert licenses.status_code == 200
    assert any(l["order_id"] == order_id for l in licenses.json())
