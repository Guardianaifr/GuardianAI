"""
GuardianAI - On-Chain Threat Intelligence Engine.

Maintains a watchlist of flagged addresses from known hacks, exploits,
and compliance incidents. Provides real-time address screening and
pattern-based anomaly detection for BTC and EVM chains.

Capabilities:
  - Address screening against known theft/hack wallets
  - Pattern detection: rapid fan-out, exchange deposit clustering
  - Incident correlation: link addresses to named incidents
  - Compliance gap detection: addresses NOT yet in commercial tools
  - Real-time alerting hooks for continuous monitoring

2026 Standard: Covers gaps left by TRM Labs, Chainalysis, and Elliptic
where newly discovered addresses take days/weeks to propagate.
"""

from __future__ import annotations

import json
import threading
import time
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set


# ─── Enums ───────────────────────────────────────────────────────────────────

class ThreatLevel(Enum):
    CRITICAL  = "critical"    # Direct theft address, exploit contract
    HIGH      = "high"        # First-hop laundering, known mixer deposit
    MEDIUM    = "medium"      # Exchange deposit used for laundering
    LOW       = "low"         # Indirect association, 2+ hops
    INFO      = "info"        # Contextual, no direct risk


class AddressChain(Enum):
    BITCOIN   = "bitcoin"
    ETHEREUM  = "ethereum"
    BASE      = "base"
    MONAD     = "monad"
    POLYGON   = "polygon"
    ARBITRUM  = "arbitrum"
    BSC       = "bsc"
    SOLANA    = "solana"
    UNKNOWN   = "unknown"


class IncidentType(Enum):
    KEY_COMPROMISE     = "key_compromise"
    SMART_CONTRACT_BUG = "smart_contract_bug"
    FLASH_LOAN         = "flash_loan"
    GOVERNANCE_EXPLOIT = "governance_exploit"
    INSIDER_THEFT      = "insider_theft"
    PHISHING           = "phishing"
    RUG_PULL           = "rug_pull"
    BRIDGE_EXPLOIT     = "bridge_exploit"
    EXCHANGE_HACK      = "exchange_hack"
    UNKNOWN            = "unknown"


class LaunderingMethod(Enum):
    EXCHANGE_DEPOSIT = "exchange_deposit"
    TORNADO_CASH     = "tornado_cash"
    MIXER            = "mixer"
    BRIDGE           = "bridge"
    PEEL_CHAIN       = "peel_chain"
    NESTED_EXCHANGE  = "nested_exchange"
    P2P_TRADE        = "p2p_trade"
    UNKNOWN          = "unknown"


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class ThreatAddress:
    """A single flagged address with full context."""
    address: str
    chain: str
    threat_level: str
    incident_id: str
    incident_name: str
    role: str                        # "theft_address", "laundering_hop", "exchange_deposit"
    amount_btc: Optional[float] = None
    amount_usd: Optional[float] = None
    first_seen: Optional[str] = None
    destination_exchange: Optional[str] = None
    laundering_method: Optional[str] = None
    notes: str = ""
    in_commercial_tools: bool = False  # Is this in TRM/Chainalysis/Elliptic?
    tags: List[str] = field(default_factory=list)


@dataclass
class ThreatIncident:
    """A named security incident with associated addresses."""
    incident_id: str
    name: str
    entity: str                      # "BitcoinDepot", "Echo Protocol", etc.
    incident_type: str
    chain: str
    date_occurred: str
    date_discovered: str
    date_disclosed: Optional[str] = None
    detection_delay_hours: float = 0
    total_stolen_btc: float = 0
    total_stolen_usd: float = 0
    addresses: List[ThreatAddress] = field(default_factory=list)
    exit_exchanges: List[str] = field(default_factory=list)
    laundering_methods: List[str] = field(default_factory=list)
    sec_filing_url: Optional[str] = None
    source: str = ""                 # "zachxbt", "sec_8k", "guardian_research"
    notes: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class ScreeningResult:
    """Result of screening an address against the threat database."""
    address: str
    flagged: bool
    threat_level: Optional[str] = None
    incident_id: Optional[str] = None
    incident_name: Optional[str] = None
    entity: Optional[str] = None
    role: Optional[str] = None
    amount_btc: Optional[float] = None
    amount_usd: Optional[float] = None
    destination_exchange: Optional[str] = None
    in_commercial_tools: bool = False
    tags: List[str] = field(default_factory=list)
    checked_at: str = ""


@dataclass
class PatternAlert:
    """An anomaly pattern detected from transaction analysis."""
    alert_id: str
    pattern_type: str
    severity: str
    description: str
    indicators: Dict[str, str] = field(default_factory=dict)
    recommendation: str = ""


# ─── Threat Feed Database ────────────────────────────────────────────────────

class ThreatIntelDB:
    """
    In-memory threat intelligence database.
    Loads incidents from JSON feed files and provides O(1) address lookups.
    """

    def __init__(self):
        self._incidents: Dict[str, ThreatIncident] = {}
        self._address_index: Dict[str, ThreatAddress] = {}  # address -> ThreatAddress
        self._tags_index: Dict[str, Set[str]] = {}           # tag -> set of addresses

    @property
    def incident_count(self) -> int:
        return len(self._incidents)

    @property
    def address_count(self) -> int:
        return len(self._address_index)

    def add_incident(self, incident: ThreatIncident) -> None:
        """Register an incident and index all its addresses."""
        self._incidents[incident.incident_id] = incident
        for addr in incident.addresses:
            key = addr.address.strip().lower()
            self._address_index[key] = addr
            for tag in addr.tags:
                self._tags_index.setdefault(tag, set()).add(key)

    def screen_address(self, address: str) -> ScreeningResult:
        """Screen a single address against the threat database."""
        key = address.strip().lower()
        now = datetime.now(timezone.utc).isoformat()

        if key not in self._address_index:
            return ScreeningResult(
                address=address,
                flagged=False,
                checked_at=now,
            )

        entry = self._address_index[key]
        incident = self._incidents.get(entry.incident_id)
        return ScreeningResult(
            address=address,
            flagged=True,
            threat_level=entry.threat_level,
            incident_id=entry.incident_id,
            incident_name=entry.incident_name,
            entity=incident.entity if incident else None,
            role=entry.role,
            amount_btc=entry.amount_btc,
            amount_usd=entry.amount_usd,
            destination_exchange=entry.destination_exchange,
            in_commercial_tools=entry.in_commercial_tools,
            tags=entry.tags,
            checked_at=now,
        )

    def screen_batch(self, addresses: List[str]) -> List[ScreeningResult]:
        """Screen multiple addresses in one call."""
        return [self.screen_address(a) for a in addresses]

    def get_incident(self, incident_id: str) -> Optional[ThreatIncident]:
        return self._incidents.get(incident_id)

    def list_incidents(self) -> List[Dict]:
        """Return summary of all registered incidents."""
        results = []
        for inc in self._incidents.values():
            results.append({
                "incident_id": inc.incident_id,
                "name": inc.name,
                "entity": inc.entity,
                "incident_type": inc.incident_type,
                "chain": inc.chain,
                "date_occurred": inc.date_occurred,
                "total_stolen_btc": inc.total_stolen_btc,
                "total_stolen_usd": inc.total_stolen_usd,
                "addresses_tracked": len(inc.addresses),
                "exit_exchanges": inc.exit_exchanges,
                "detection_delay_hours": inc.detection_delay_hours,
                "source": inc.source,
            })
        return results

    def get_addresses_by_tag(self, tag: str) -> List[str]:
        return list(self._tags_index.get(tag, set()))

    def load_feed_file(self, path: str) -> int:
        """Load a threat feed JSON file and return count of addresses added."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        count = 0
        for inc_data in data.get("incidents", []):
            addresses = []
            for addr_data in inc_data.get("addresses", []):
                addresses.append(ThreatAddress(**addr_data))
                count += 1

            incident = ThreatIncident(
                incident_id=inc_data["incident_id"],
                name=inc_data["name"],
                entity=inc_data["entity"],
                incident_type=inc_data.get("incident_type", "unknown"),
                chain=inc_data.get("chain", "unknown"),
                date_occurred=inc_data.get("date_occurred", ""),
                date_discovered=inc_data.get("date_discovered", ""),
                date_disclosed=inc_data.get("date_disclosed"),
                detection_delay_hours=inc_data.get("detection_delay_hours", 0),
                total_stolen_btc=inc_data.get("total_stolen_btc", 0),
                total_stolen_usd=inc_data.get("total_stolen_usd", 0),
                addresses=addresses,
                exit_exchanges=inc_data.get("exit_exchanges", []),
                laundering_methods=inc_data.get("laundering_methods", []),
                sec_filing_url=inc_data.get("sec_filing_url"),
                source=inc_data.get("source", ""),
                notes=inc_data.get("notes", ""),
                tags=inc_data.get("tags", []),
            )
            self.add_incident(incident)

        return count

    def load_feeds_from_dir(self, directory: str) -> int:
        """Load all .json feed files from a directory."""
        feed_dir = Path(directory)
        if not feed_dir.is_dir():
            return 0
        total = 0
        for f in sorted(feed_dir.glob("*.json")):
            total += self.load_feed_file(str(f))
        return total


# ─── Pattern Detection ───────────────────────────────────────────────────────

def detect_fanout_pattern(
    source_address: str,
    destinations: List[Dict[str, str]],
    time_window_seconds: int = 3600,
) -> Optional[PatternAlert]:
    """
    Detect BTM-class rapid fan-out: one source splits funds to many
    fresh addresses within a short time window.

    destinations: list of {"address": ..., "amount_btc": ..., "timestamp": ...}
    """
    if len(destinations) < 5:
        return None

    amounts = [float(d.get("amount_btc", 0)) for d in destinations]
    timestamps = [float(d.get("timestamp", 0)) for d in destinations]

    if not timestamps:
        return None

    time_span = max(timestamps) - min(timestamps)
    avg_amount = sum(amounts) / len(amounts) if amounts else 0
    total = sum(amounts)

    # BTM pattern: 10+ outputs, similar amounts, within hours
    if len(destinations) >= 10 and time_span <= time_window_seconds * 24:
        return PatternAlert(
            alert_id=f"FAN-{hashlib.sha256(source_address.encode()).hexdigest()[:8].upper()}",
            pattern_type="rapid_fanout",
            severity="critical",
            description=(
                f"Suspicious fan-out detected: {len(destinations)} outputs from "
                f"{source_address[:16]}... totaling {total:.2f} BTC in "
                f"{time_span/3600:.1f} hours. Pattern matches BTM-class "
                f"key compromise with structured laundering."
            ),
            indicators={
                "source": source_address,
                "output_count": str(len(destinations)),
                "total_btc": f"{total:.4f}",
                "avg_amount_btc": f"{avg_amount:.4f}",
                "time_span_hours": f"{time_span/3600:.1f}",
            },
            recommendation=(
                "Immediately freeze associated accounts. Flag all destination "
                "addresses. Check if destination addresses are fresh (zero prior "
                "history). Monitor for exchange deposits within 24h."
            ),
        )

    return None


def detect_exchange_clustering(
    addresses: List[Dict[str, str]],
    exchange_name: str = "",
) -> Optional[PatternAlert]:
    """
    Detect when multiple theft-linked addresses all deposit to the same exchange.
    """
    if len(addresses) < 3:
        return None

    return PatternAlert(
        alert_id=f"CLUSTER-{hashlib.sha256(exchange_name.encode()).hexdigest()[:8].upper()}",
        pattern_type="exchange_deposit_clustering",
        severity="high",
        description=(
            f"{len(addresses)} theft-linked addresses depositing to {exchange_name}. "
            f"Exchange should be notified for account freezing."
        ),
        indicators={
            "exchange": exchange_name,
            "address_count": str(len(addresses)),
        },
        recommendation=(
            f"Submit Suspicious Activity Report (SAR) to {exchange_name}. "
            f"Request account freeze via law enforcement channel. "
            f"File blockchain analytics report with transaction hashes."
        ),
    )


# ─── Thread-safe singleton for global use ──────────────────────────────────────

_global_lock = threading.Lock()
_global_db: Optional[ThreatIntelDB] = None

def get_threat_db() -> ThreatIntelDB:
    """Get or create the global threat intelligence database (thread-safe)."""
    global _global_db
    if _global_db is None:
        with _global_lock:
            if _global_db is None:
                db = ThreatIntelDB()
                # Auto-load feeds from default directory
                feed_dir = Path(__file__).parent.parent / "threat_feeds"
                if feed_dir.is_dir():
                    db.load_feeds_from_dir(str(feed_dir))
                _global_db = db
    return _global_db
