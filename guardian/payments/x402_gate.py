"""Pay-per-approval for ``POST /api/v1/attest`` using x402 (USDC on Monad).

Off by default. Turn on with ``GUARDIAN_X402_ENABLED=true``.

Flow (x402 "exact" scheme, EIP-3009 transferWithAuthorization):
  1. Agent calls /api/v1/attest with no payment  -> 402 + PAYMENT-REQUIRED header.
  2. Agent signs a USDC authorization and retries with PAYMENT-SIGNATURE.
  3. Facilitator verifies it, the relay evaluates the action.
  4. Only an *approved* attestation (HTTP 2xx) is settled on-chain.
     A blocked action returns 403, so the agent is never charged for it.

Free tier: the first GUARDIAN_X402_FREE_PER_AGENT_MONTH approvals per agent_id
per calendar month skip payment. agent_id is self-declared, so the free tier is
a convenience, not an abuse control; set it to 0 to disable.

Env:
  GUARDIAN_X402_ENABLED               true/false (default false)
  GUARDIAN_X402_PAY_TO                address that receives USDC (required when enabled)
  GUARDIAN_X402_PRICE                 default "$0.01"
  GUARDIAN_X402_NETWORK               default "eip155:10143" (Monad testnet)
  GUARDIAN_X402_FACILITATOR_URL       default https://x402-facilitator.molandak.org
  GUARDIAN_X402_FREE_PER_AGENT_MONTH  default 0
"""
from __future__ import annotations

import io
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

ATTEST_PATH = "/api/v1/attest"
DEFAULT_FACILITATOR = "https://x402-facilitator.molandak.org"
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def x402_enabled() -> bool:
    return os.environ.get("GUARDIAN_X402_ENABLED", "false").strip().lower() == "true"


class FreeTierCounter:
    """Counts free approvals per agent_id per calendar month (UTC) in SQLite."""

    def __init__(self, db_path: str, limit: int):
        self.db_path = db_path
        self.limit = max(0, int(limit))
        self._lock = threading.Lock()
        with sqlite3.connect(self.db_path) as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS x402_free_usage ("
                "agent_id TEXT NOT NULL, month TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0,"
                "PRIMARY KEY (agent_id, month))"
            )

    @staticmethod
    def _month() -> str:
        return time.strftime("%Y-%m", time.gmtime())

    def remaining(self, agent_id: str) -> int:
        if self.limit == 0 or not agent_id:
            return 0
        with sqlite3.connect(self.db_path) as c:
            row = c.execute(
                "SELECT used FROM x402_free_usage WHERE agent_id=? AND month=?",
                (agent_id.lower(), self._month()),
            ).fetchone()
        return max(0, self.limit - (row[0] if row else 0))

    def consume(self, agent_id: str) -> None:
        with self._lock, sqlite3.connect(self.db_path) as c:
            c.execute(
                "INSERT INTO x402_free_usage(agent_id, month, used) VALUES(?,?,1) "
                "ON CONFLICT(agent_id, month) DO UPDATE SET used = used + 1",
                (agent_id.lower(), self._month()),
            )


def _read_agent_id(environ: dict) -> tuple[Optional[str], bytes]:
    """Buffer the request body so both the gate and Flask can read it."""
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    body = environ["wsgi.input"].read(length) if length > 0 else b""
    environ["wsgi.input"] = io.BytesIO(body)
    try:
        data = json.loads(body or b"{}")
        agent_id = data.get("agent_id") if isinstance(data, dict) else None
        return (str(agent_id) if agent_id else None), body
    except (ValueError, UnicodeDecodeError):
        return None, body


def install_x402_gate(app: Any, db_path: str) -> Optional[dict]:
    """Wrap ``app.wsgi_app`` with the x402 paywall for /api/v1/attest.

    Returns a dict describing the active config, or None when disabled.
    Raises ValueError on bad config so a misconfigured paywall never starts open.
    """
    if not x402_enabled():
        return None

    pay_to = os.environ.get("GUARDIAN_X402_PAY_TO", "").strip()
    if not _ADDR.match(pay_to):
        raise ValueError("GUARDIAN_X402_ENABLED=true but GUARDIAN_X402_PAY_TO is not a valid address")
    price = os.environ.get("GUARDIAN_X402_PRICE", "$0.01").strip()
    network = os.environ.get("GUARDIAN_X402_NETWORK", "eip155:10143").strip()
    facilitator_url = os.environ.get("GUARDIAN_X402_FACILITATOR_URL", DEFAULT_FACILITATOR).strip()
    free_limit = int(os.environ.get("GUARDIAN_X402_FREE_PER_AGENT_MONTH", "0") or 0)

    from x402 import x402ResourceServerSync
    from x402.http import FacilitatorConfig, HTTPFacilitatorClientSync, PaymentOption
    from x402.http.middleware.flask import PaymentMiddleware
    from x402.http.types import RouteConfig
    from x402.mechanisms.evm.exact import register_exact_evm_server

    server = x402ResourceServerSync(HTTPFacilitatorClientSync(FacilitatorConfig(url=facilitator_url)))
    register_exact_evm_server(server, network)
    routes = {
        f"POST {ATTEST_PATH}": RouteConfig(
            accepts=[PaymentOption(scheme="exact", pay_to=pay_to, price=price, network=network)],
            description="GuardianAI signed safety attestation (charged only when approved)",
            mime_type="application/json",
        )
    }

    unpaid_wsgi: Callable = app.wsgi_app
    PaymentMiddleware(app, routes, server)  # replaces app.wsgi_app with the paid pipeline
    paid_wsgi: Callable = app.wsgi_app
    counter = FreeTierCounter(db_path, free_limit)

    def gate(environ, start_response):
        if environ.get("PATH_INFO") != ATTEST_PATH or environ.get("REQUEST_METHOD") != "POST":
            return unpaid_wsgi(environ, start_response)
        agent_id, _ = _read_agent_id(environ)
        if agent_id and counter.remaining(agent_id) > 0:
            status_holder: dict = {}

            def _sr(status, headers, exc_info=None):
                status_holder["code"] = int(status.split(" ", 1)[0])
                headers = list(headers) + [("X-Guardian-Billing", "free-tier")]
                return start_response(status, headers, exc_info)

            result = unpaid_wsgi(environ, _sr)
            if 200 <= status_holder.get("code", 500) < 300:
                counter.consume(agent_id)
            return result
        return paid_wsgi(environ, start_response)

    app.wsgi_app = gate
    cfg = {"pay_to": pay_to, "price": price, "network": network,
           "facilitator": facilitator_url, "free_per_agent_month": free_limit}
    logger.info("x402 paywall active on %s: %s", ATTEST_PATH, cfg)
    return cfg
