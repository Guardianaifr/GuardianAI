"""Per-agent rules for the attestation relay: who an agent may pay, how much, and how.

Rules live in a JSON file (GUARDIAN_AGENT_POLICIES_FILE, default config/agent_policies.json):

{
  "default": {                       # applies to every agent without its own entry
    "max_value_per_tx_mon": "1",     # native MON per payment
    "max_daily_outflow_mon": "5",    # native MON per rolling 24h
    "max_token_per_tx": {"0x534b…43A3": "100"},  # token units per transfer (decimal, uses decimals below)
    "token_decimals": {"0x534b…43A3": 6},
    "allowed_recipients": null,      # null = anyone not on the scam list; list = only these
    "allowed_selectors": null,       # null = any function; list = only these 4-byte selectors
    "require_prompt": false          # true = refuse requests that don't include the prompt
  },
  "agents": { "<agent_id>": { ...same fields... } }
}

If the file is missing, BUILT_IN_DEFAULT applies, so a fresh install is capped, not open.
"""
from __future__ import annotations

import json
import os
import threading
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

USDC_MONAD_TESTNET = "0x534b2f3a21130d7a60830c2df862319e593943a3"

BUILT_IN_DEFAULT: Dict[str, Any] = {
    "max_value_per_tx_mon": "1",
    "max_daily_outflow_mon": "5",
    "max_token_per_tx": {USDC_MONAD_TESTNET: "100"},
    "token_decimals": {USDC_MONAD_TESTNET: 6},
    "allowed_recipients": None,
    "allowed_selectors": None,
    "require_prompt": False,
}

_ALLOWED_KEYS = set(BUILT_IN_DEFAULT)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _wei(mon: Optional[str]) -> Optional[int]:
    if mon is None:
        return None
    v = Decimal(str(mon))
    if v < 0:
        raise ValueError("amounts must be >= 0")
    return int(v * 10**18)


def _addr_list(xs) -> Optional[set]:
    if xs is None:
        return None
    out = set()
    for a in xs:
        a = str(a).strip().lower()
        if not (a.startswith("0x") and len(a) == 42):
            raise ValueError(f"not an address: {a}")
        out.add(a)
    return out


def build_policy(spec: Dict[str, Any]):
    """Validate a JSON rule object and turn it into an AgentPolicy."""
    from guardian.relayer.attestation_service import AgentPolicy

    unknown = set(spec) - _ALLOWED_KEYS
    if unknown:
        raise ValueError(f"unknown rule fields: {sorted(unknown)}")
    decimals = {k.lower(): int(v) for k, v in (spec.get("token_decimals") or {}).items()}
    token_caps = {}
    for tok, amt in (spec.get("max_token_per_tx") or {}).items():
        tok = tok.lower()
        if tok not in decimals:
            raise ValueError(f"token_decimals missing for {tok}")
        token_caps[tok] = int(Decimal(str(amt)) * 10 ** decimals[tok])
    sels = spec.get("allowed_selectors")
    return AgentPolicy(
        allowed_selectors=None if sels is None else {s.lower() for s in sels},
        max_value_per_tx=_wei(spec.get("max_value_per_tx_mon")),
        max_daily_outflow=_wei(spec.get("max_daily_outflow_mon")),
        allowed_recipients=_addr_list(spec.get("allowed_recipients")),
        max_token_per_tx=token_caps or None,
        require_prompt=bool(spec.get("require_prompt", False)),
    )


class AgentRulesStore:
    """Loads rules from disk and lets the relay update one agent's rules (persisted)."""

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or os.environ.get("GUARDIAN_AGENT_POLICIES_FILE") or REPO_ROOT / "config" / "agent_policies.json")
        self._lock = threading.Lock()
        self.raw: Dict[str, Any] = {"default": dict(BUILT_IN_DEFAULT), "agents": {}}
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.raw = {"default": {**BUILT_IN_DEFAULT, **(data.get("default") or {})},
                        "agents": data.get("agents") or {}}
        self.default = build_policy(self.raw["default"])
        self.per_agent = {aid: build_policy({**self.raw["default"], **spec}) for aid, spec in self.raw["agents"].items()}

    def rules_for(self, agent_id: str) -> Tuple[Dict[str, Any], bool]:
        spec = self.raw["agents"].get(agent_id)
        return ({**self.raw["default"], **spec} if spec else dict(self.raw["default"])), spec is not None

    def set_agent(self, agent_id: str, spec: Dict[str, Any]):
        merged = {**self.raw["default"], **spec}
        policy = build_policy(merged)  # validates before anything is saved
        with self._lock:
            self.raw["agents"][agent_id] = spec
            self.per_agent[agent_id] = policy
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.raw, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        return policy
