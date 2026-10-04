"""The feed a Chainlink CRE workflow reads to write GuardianAI's scam list on-chain (GuardianThreatOracle).

Every DON node fetches GET /api/v1/threat-oracle/feed independently. The nodes must agree on `entries`
and `digest` exactly (identical consensus) and take the median of the counters, so the response must be
deterministic: entries are sorted, de-duplicated and serialised canonically, and `digest` is
keccak256(canonical entries JSON). The workflow recomputes the digest before it signs a report.

Feed file (default config/threat_oracle_feed.json, override with GUARDIAN_THREAT_ORACLE_FEED):
    {"entries": [{"address": "0x...", "flagged": true, "reason": "..."}]}
`flagged: false` entries un-flag an address on-chain.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from web3 import Web3

MAX_ENTRIES = 100  # GuardianThreatOracle.MAX_ADDRESSES_PER_REPORT
DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "threat_oracle_feed.json"


def load_entries(path: Optional[str] = None) -> List[Dict[str, Any]]:
    p = Path(path or os.environ.get("GUARDIAN_THREAT_ORACLE_FEED") or DEFAULT_PATH)
    if not p.exists():
        return []
    raw = json.loads(p.read_text(encoding="utf-8"))
    by_addr: Dict[str, bool] = {}
    for e in raw.get("entries", []):
        addr = str(e.get("address", "")).strip()
        if not Web3.is_address(addr):
            raise ValueError(f"Invalid address in threat oracle feed: {addr!r}")
        by_addr[addr.lower()] = bool(e.get("flagged", True))  # last entry for an address wins
    entries = [{"address": a, "flagged": f} for a, f in sorted(by_addr.items())]
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"Threat oracle feed has {len(entries)} entries; max per report is {MAX_ENTRIES}")
    return entries


def canonical_entries_json(entries: List[Dict[str, Any]]) -> str:
    return json.dumps(entries, separators=(",", ":"), sort_keys=True)


def build_feed(stats: Dict[str, int], path: Optional[str] = None) -> Dict[str, Any]:
    entries = load_entries(path)
    canon = canonical_entries_json(entries)
    digest = "0x" + Web3.keccak(text=canon).hex().removeprefix("0x")
    return {
        "stats": {
            "blocked": int(stats.get("blocked", 0)),
            "intercepted": int(stats.get("intercepted", 0)),
            "passed": int(stats.get("passed", 0)),
        },
        "entries_json": canon,
        "digest": digest,
        "count": len(entries),
    }
