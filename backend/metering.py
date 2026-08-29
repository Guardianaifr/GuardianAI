"""
Usage Metering & Pricing Tiers for GuardianAI.

Tracks per-tenant request volume, token consumption, and enforces
tier-based rate limits. Provides usage dashboard data and billing
integration hooks.

Pricing Tiers:
  - free:       50 requests/day, 10K tokens/day, community support
  - starter:    5,000 requests/day, 500K tokens/day ($49/mo)
  - pro:        50,000 requests/day, 5M tokens/day ($299/mo)
  - enterprise: unlimited, custom SLA, dedicated support (custom)
"""
from __future__ import annotations

import sqlite3
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Pricing Tier Definitions
# ---------------------------------------------------------------------------

@dataclass
class PricingTier:
    """Definition of a pricing tier with limits and pricing."""
    name: str
    display_name: str
    monthly_usd: float
    daily_request_limit: int
    daily_token_limit: int
    max_system_prompt_length: int
    features: List[str]
    support_level: str
    sla_pct: float = 0.0


PRICING_TIERS: Dict[str, PricingTier] = {
    "free": PricingTier(
        name="free",
        display_name="Free",
        monthly_usd=0,
        daily_request_limit=50,
        daily_token_limit=10_000,
        max_system_prompt_length=500,
        features=[
            "Basic prompt injection detection",
            "PII redaction (5 entity types)",
            "Community support",
        ],
        support_level="community",
        sla_pct=0.0,
    ),
    "starter": PricingTier(
        name="starter",
        display_name="Starter",
        monthly_usd=49,
        daily_request_limit=5_000,
        daily_token_limit=500_000,
        max_system_prompt_length=2_000,
        features=[
            "All Free features",
            "AI-powered injection classifier",
            "Full PII redaction (12+ entity types)",
            "System prompt leakage protection",
            "Email support (48h SLA)",
        ],
        support_level="email",
        sla_pct=99.0,
    ),
    "pro": PricingTier(
        name="pro",
        display_name="Pro",
        monthly_usd=299,
        daily_request_limit=50_000,
        daily_token_limit=5_000_000,
        max_system_prompt_length=10_000,
        features=[
            "All Starter features",
            "SIEM integration",
            "Differential privacy analytics",
            "Multi-tenant isolation",
            "Custom guardrails",
            "EU AI Act compliance reports",
            "Priority support (24h SLA)",
        ],
        support_level="priority",
        sla_pct=99.9,
    ),
    "enterprise": PricingTier(
        name="enterprise",
        display_name="Enterprise",
        monthly_usd=0,  # Custom pricing
        daily_request_limit=0,  # Unlimited (0 = no limit)
        daily_token_limit=0,  # Unlimited
        max_system_prompt_length=0,  # Unlimited
        features=[
            "All Pro features",
            "Unlimited requests & tokens",
            "Dedicated infrastructure",
            "Custom SLA (up to 99.99%)",
            "On-premise deployment option",
            "24/7 dedicated support",
            "Quarterly security reviews",
        ],
        support_level="dedicated",
        sla_pct=99.99,
    ),
}


# ---------------------------------------------------------------------------
# Usage Record
# ---------------------------------------------------------------------------

@dataclass
class UsageRecord:
    """Summary of a tenant's usage for a time period."""
    tenant_id: str
    tier: str
    period_start: float
    period_end: float
    request_count: int
    token_count: int
    request_limit: int
    token_limit: int
    request_usage_pct: float
    token_usage_pct: float
    is_rate_limited: bool


@dataclass
class MeteringDecision:
    """Result of a metering check."""
    allowed: bool
    reason: str
    remaining_requests: int
    remaining_tokens: int
    tier: str
    usage_pct: float


# ---------------------------------------------------------------------------
# Usage Metering Engine
# ---------------------------------------------------------------------------

class UsageMeter:
    """Per-tenant usage tracking and tier enforcement.

    Uses SQLite for durable metering with in-memory caching for
    hot-path performance. Thread-safe via locking.

    Args:
        db_path: Path to SQLite database.
    """

    def __init__(self, db_path: str = "guardian.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Create metering tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usage_metering (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                request_count INTEGER DEFAULT 0,
                token_count INTEGER DEFAULT 0,
                period_date TEXT NOT NULL,
                updated_at REAL,
                UNIQUE(tenant_id, period_date)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS tenant_tiers (
                tenant_id TEXT PRIMARY KEY,
                tier TEXT NOT NULL DEFAULT 'free',
                updated_at REAL
            )
        """)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Tier Management
    # ------------------------------------------------------------------

    def set_tenant_tier(self, tenant_id: str, tier: str) -> None:
        """Set a tenant's pricing tier."""
        if tier not in PRICING_TIERS:
            raise ValueError(f"Invalid tier: {tier}. Must be one of: {list(PRICING_TIERS.keys())}")
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO tenant_tiers (tenant_id, tier, updated_at) VALUES (?, ?, ?)",
            (tenant_id, tier, time.time()),
        )
        conn.commit()
        conn.close()

    def get_tenant_tier(self, tenant_id: str) -> str:
        """Get a tenant's pricing tier (default: 'free')."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT tier FROM tenant_tiers WHERE tenant_id = ?", (tenant_id,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else "free"

    # ------------------------------------------------------------------
    # Usage Recording
    # ------------------------------------------------------------------

    def record_usage(self, tenant_id: str, tokens: int = 0) -> MeteringDecision:
        """Record a request and check if tenant is within limits.

        This is the hot-path method called on every proxied request.

        Args:
            tenant_id: The tenant making the request.
            tokens: Number of tokens consumed (estimated or actual).

        Returns:
            MeteringDecision indicating if the request is allowed.
        """
        today = time.strftime("%Y-%m-%d", time.gmtime())

        with self._lock:
            tier_name = self.get_tenant_tier(tenant_id)
            tier = PRICING_TIERS.get(tier_name, PRICING_TIERS["free"])
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()

            # Upsert today's usage record
            cur.execute(
                """
                INSERT INTO usage_metering (tenant_id, request_count, token_count, period_date, updated_at)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(tenant_id, period_date) DO UPDATE SET
                    request_count = request_count + 1,
                    token_count = token_count + ?,
                    updated_at = ?
                """,
                (tenant_id, tokens, today, time.time(), tokens, time.time()),
            )
            conn.commit()

            # Get current usage
            cur.execute(
                "SELECT request_count, token_count FROM usage_metering WHERE tenant_id = ? AND period_date = ?",
                (tenant_id, today),
            )
            row = cur.fetchone()
            conn.close()

        current_requests = row[0] if row else 1
        current_tokens = row[1] if row else tokens

        # Check limits (0 = unlimited for enterprise)
        request_limit = tier.daily_request_limit
        token_limit = tier.daily_token_limit

        request_exceeded = request_limit > 0 and current_requests > request_limit
        token_exceeded = token_limit > 0 and current_tokens > token_limit

        if request_exceeded or token_exceeded:
            import os
            # Beta: pricing enforcement disabled when GUARDIAN_BETA_MODE=true.
            if os.getenv('GUARDIAN_BETA_MODE', 'false').lower() in ('true', '1'):
                pass
            else:
                reason = "request_limit_exceeded" if request_exceeded else "token_limit_exceeded"
                usage_pct = (current_requests / request_limit * 100) if request_limit > 0 else 0
                return MeteringDecision(
                    allowed=False,
                    reason=reason,
                    remaining_requests=max(0, request_limit - current_requests) if request_limit > 0 else 999999,
                    remaining_tokens=max(0, token_limit - current_tokens) if token_limit > 0 else 999999,
                    tier=tier_name,
                    usage_pct=min(100.0, usage_pct),
                )

        remaining_req = (request_limit - current_requests) if request_limit > 0 else 999999
        remaining_tok = (token_limit - current_tokens) if token_limit > 0 else 999999
        usage_pct = (current_requests / request_limit * 100) if request_limit > 0 else 0

        return MeteringDecision(
            allowed=True,
            reason="ok",
            remaining_requests=remaining_req,
            remaining_tokens=remaining_tok,
            tier=tier_name,
            usage_pct=round(usage_pct, 1),
        )

    # ------------------------------------------------------------------
    # Usage Reporting
    # ------------------------------------------------------------------

    def get_usage(self, tenant_id: str, date: Optional[str] = None) -> UsageRecord:
        """Get usage summary for a tenant.

        Args:
            tenant_id: Tenant to query.
            date: Date string (YYYY-MM-DD). Defaults to today.

        Returns:
            UsageRecord with current usage stats.
        """
        if date is None:
            date = time.strftime("%Y-%m-%d", time.gmtime())

        tier_name = self.get_tenant_tier(tenant_id)
        tier = PRICING_TIERS.get(tier_name, PRICING_TIERS["free"])

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT request_count, token_count FROM usage_metering WHERE tenant_id = ? AND period_date = ?",
            (tenant_id, date),
        )
        row = cur.fetchone()
        conn.close()

        request_count = row[0] if row else 0
        token_count = row[1] if row else 0
        req_limit = tier.daily_request_limit
        tok_limit = tier.daily_token_limit

        req_pct = (request_count / req_limit * 100) if req_limit > 0 else 0
        tok_pct = (token_count / tok_limit * 100) if tok_limit > 0 else 0

        # Parse period start/end from date string
        try:
            import datetime
            dt = datetime.datetime.strptime(date, "%Y-%m-%d")
            period_start = dt.timestamp()
            period_end = period_start + 86400
        except Exception:
            period_start = time.time()
            period_end = period_start + 86400

        return UsageRecord(
            tenant_id=tenant_id,
            tier=tier_name,
            period_start=period_start,
            period_end=period_end,
            request_count=request_count,
            token_count=token_count,
            request_limit=req_limit,
            token_limit=tok_limit,
            request_usage_pct=round(req_pct, 1),
            token_usage_pct=round(tok_pct, 1),
            is_rate_limited=req_pct > 100 or tok_pct > 100,
        )

    def get_usage_history(self, tenant_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get usage history for the last N days.

        Args:
            tenant_id: Tenant to query.
            days: Number of days to look back.

        Returns:
            List of daily usage dicts.
        """
        import datetime
        cutoff = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)).strftime("%Y-%m-%d")

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT period_date, request_count, token_count FROM usage_metering "
            "WHERE tenant_id = ? AND period_date >= ? ORDER BY period_date",
            (tenant_id, cutoff),
        )
        rows = cur.fetchall()
        conn.close()

        return [
            {"date": r[0], "requests": r[1], "tokens": r[2]}
            for r in rows
        ]

    def get_all_tenant_usage(self) -> List[Dict[str, Any]]:
        """Get today's usage for all tenants (admin view)."""
        today = time.strftime("%Y-%m-%d", time.gmtime())
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT m.tenant_id, m.request_count, m.token_count, "
            "COALESCE(t.tier, 'free') as tier "
            "FROM usage_metering m "
            "LEFT JOIN tenant_tiers t ON m.tenant_id = t.tenant_id "
            "WHERE m.period_date = ? ORDER BY m.request_count DESC",
            (today,),
        )
        rows = cur.fetchall()
        conn.close()

        results = []
        for r in rows:
            tier = PRICING_TIERS.get(r[3], PRICING_TIERS["free"])
            req_limit = tier.daily_request_limit
            results.append({
                "tenant_id": r[0],
                "requests": r[1],
                "tokens": r[2],
                "tier": r[3],
                "usage_pct": round(r[1] / req_limit * 100, 1) if req_limit > 0 else 0,
            })
        return results
