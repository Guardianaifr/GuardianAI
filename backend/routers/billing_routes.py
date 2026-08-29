from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import time
import sqlite3
import secrets
import requests

from backend.main import (
    BILLING_MODE,
    BillingCheckoutRequest,
    BillingConfirmRequest,
    CHECKOUT_CANCEL_URL,
    CHECKOUT_SUCCESS_URL,
    CRYPTO_API_KEY,
    DB_PATH,
    STRIPE_PRICE_ENTERPRISE,
    STRIPE_PRICE_PRO,
    STRIPE_PRICE_STARTER,
    STRIPE_SECRET_KEY,
    _build_checkout_url,
    _upsert_customer,
    enforce_admin_rate_limit,
    enforce_user_rate_limit,
)

router = APIRouter()
VALID_PLANS = {"free", "starter", "pro", "enterprise", "lifetime"}

@router.get("/api/v1/public/plans")
async def public_plans():
    return {
        "billing_mode": BILLING_MODE,
        "plans": {
            "free": {
                "name": "Free Scan",
                "description": "Quick endpoint posture checks for Web3 AI-agent demos.",
                "amount_usd": 0,
                "billing_cycle": "free",
            },
            "starter": {
                "name": "Starter",
                "description": "Deep scans, CI reports, SARIF export, and signed evidence badges.",
                "amount_usd": 49,
                "billing_cycle": "monthly",
            },
            "pro": {
                "name": "Pro Gateway",
                "description": "Runtime prompt, output, wallet-action, and tool-call guardrails.",
                "amount_usd": 299,
                "billing_cycle": "monthly",
            },
            "enterprise": {
                "name": "Enterprise",
                "description": "Private deployment, custom policies, and procurement support.",
                "amount_usd": None,
                "billing_cycle": "custom",
            },
        },
        "payment_methods": ["card", "crypto"],
    }


@router.post("/api/v1/billing/checkout")
async def billing_checkout(payload: BillingCheckoutRequest, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    if payload.plan not in VALID_PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")
    now = time.time()
    order_id = f"ord_{secrets.token_hex(8)}"
    provider = "mock"
    checkout_url = _build_checkout_url(order_id)

    if BILLING_MODE == "live" and payload.payment_method == "card":
        provider = "stripe"
        price_id = STRIPE_PRICE_STARTER or STRIPE_PRICE_PRO or STRIPE_PRICE_ENTERPRISE
        if not STRIPE_SECRET_KEY or not price_id:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Stripe is not configured")
        response = requests.post(
            "https://api.stripe.com/v1/checkout/sessions",
            headers={"Authorization": f"Bearer {STRIPE_SECRET_KEY}"},
            data={
                "mode": "payment",
                "success_url": CHECKOUT_SUCCESS_URL,
                "cancel_url": CHECKOUT_CANCEL_URL,
                "line_items[0][price]": price_id,
                "line_items[0][quantity]": "1",
            },
            timeout=10,
        )
        if response.status_code >= 300:
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Stripe checkout failed")
        checkout_url = response.json().get("url", checkout_url)
    elif payload.payment_method == "crypto":
        provider = "mock" if BILLING_MODE != "live" or not CRYPTO_API_KEY else "crypto"

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    _upsert_customer(cur, payload.customer_email, payload.tenant_name)
    cur.execute(
        """
        INSERT INTO orders (
            order_id, customer_email, tenant_name, plan, payment_method, provider, status, checkout_url, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            order_id,
            payload.customer_email,
            payload.tenant_name,
            payload.plan,
            payload.payment_method,
            provider,
            "pending",
            checkout_url,
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()
    return {"order_id": order_id, "provider": provider, "checkout_url": checkout_url}


@router.post("/api/v1/billing/confirm")
async def billing_confirm(payload: BillingConfirmRequest, username: str = Depends(enforce_admin_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE orders
        SET status = ?, provider_transaction_id = ?, updated_at = ?
        WHERE order_id = ?
        """,
        ("paid" if payload.provider_status.lower() == "confirmed" else payload.provider_status.lower(), payload.provider_transaction_id, time.time(), payload.order_id),
    )
    updated = cur.rowcount
    conn.commit()
    conn.close()
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    return {"order_id": payload.order_id, "status": "paid" if payload.provider_status.lower() == "confirmed" else payload.provider_status.lower()}


@router.get("/api/v1/orders")
async def list_orders(username: str = Depends(enforce_admin_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT order_id, customer_email, tenant_name, plan, payment_method, provider, status, checkout_url FROM orders ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "order_id": r[0],
            "customer_email": r[1],
            "tenant_name": r[2],
            "plan": r[3],
            "payment_method": r[4],
            "provider": r[5],
            "status": r[6],
            "checkout_url": r[7],
        }
        for r in rows
    ]


@router.get("/api/v1/customers")
async def list_customers(username: str = Depends(enforce_admin_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT email, tenant_name, created_at FROM customers ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [{"email": r[0], "tenant_name": r[1], "created_at": r[2]} for r in rows]


@router.delete("/api/v1/admin/tenant-data")
async def delete_tenant_data(tenant_id: str, username: str = Depends(enforce_admin_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM security_events WHERE tenant_id = ?", (tenant_id,))
    deleted_events = cur.rowcount
    cur.execute("DELETE FROM analytics WHERE tenant_id = ?", (tenant_id,))
    deleted_analytics = cur.rowcount
    conn.commit()
    conn.close()
    return {"tenant_id": tenant_id, "deleted_security_events": deleted_events, "deleted_analytics": deleted_analytics}
