"""Passkey agent cards: proof that the operator authorized an agent id for a wallet.

The operator's passkey (Mera PRF, identity namespace ``guardianai:v1:agent:identity:<agent_id>``)
derives an Ed25519 key per agent. The browser console (website/mera/) signs:

    GuardianAI agent card v1
    agent: <agent_id>
    wallet: <wallet, lowercase>
    expires: <unix seconds>

The relay keeps a registry ``{agent_id: "did:guardian:ed25519:<pubkey hex>"}``. For a registered
agent, ``/api/v1/attest`` only proceeds when the request carries a card that verifies against the
registered key, names the same wallet, and has not expired. Unregistered agents behave as before.

This closes the gap where ``agent_id`` was caller-supplied: without the operator's passkey nobody can
produce a card for a registered agent. A card is a signed statement, not a secret; it does not let
anyone spend, because GuardianAgentWallet still requires the operator key on-chain.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DID_PREFIX = "did:guardian:ed25519:"
MAX_CARD_LIFETIME_SECONDS = 30 * 86400
DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "config" / "agent_passkey_identities.json"
_DID_RE = re.compile(r"^did:guardian:ed25519:[0-9a-f]{64}$")
_SIG_RE = re.compile(r"^[0-9a-f]{128}$")
_WALLET_RE = re.compile(r"^0x[0-9a-f]{40}$")


def card_message(agent_id: str, wallet: str, expires_at: int) -> bytes:
    """Must match agentCardMessage() in metropolis/mera/src/guardian_mera_engine.ts byte for byte."""
    return (
        f"GuardianAI agent card v1\nagent: {agent_id}\nwallet: {wallet.lower()}\nexpires: {expires_at}"
    ).encode("utf-8")


@dataclass(frozen=True)
class CardCheck:
    required: bool
    ok: bool
    reason: str = ""


def load_registry(path: Optional[str] = None) -> Dict[str, str]:
    """Reads {agent_id: did}. A missing file means no agent is registered (cards not required)."""
    p = Path(path or os.environ.get("GUARDIAN_AGENT_CARD_REGISTRY") or DEFAULT_REGISTRY)
    if not p.is_file():
        return {}
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: expected a JSON object of agent_id -> did")
    registry: Dict[str, str] = {}
    for agent_id, did in raw.items():
        if agent_id.startswith("_"):  # comment keys
            continue
        if not isinstance(did, str) or not _DID_RE.match(did):
            raise ValueError(f"{p}: {agent_id!r} must map to a did:guardian:ed25519:<64 hex> string")
        registry[agent_id] = did
    return registry


def verify_card(
    agent_id: str,
    wallet: Optional[str],
    card: Any,
    registry: Dict[str, str],
    now: Optional[int] = None,
) -> CardCheck:
    """Checks the card for a registered agent. Unregistered agents return required=False, ok=True."""
    did = registry.get(agent_id)
    if did is None:
        return CardCheck(required=False, ok=True)
    if not isinstance(card, dict):
        return CardCheck(True, False, "agent card required: this agent is registered to an operator passkey")
    if not wallet:
        return CardCheck(True, False, "agent card requires a GuardianAgentWallet address in 'wallet'")
    now = int(time.time()) if now is None else now
    try:
        card_agent = card["agent_id"]
        card_wallet = str(card["wallet"]).lower()
        expires_at = int(card["expires_at"])
        card_did = card["did"]
        signature = card["signature"]
    except (KeyError, TypeError, ValueError):
        return CardCheck(True, False, "malformed agent card")
    if card.get("version") != 1:
        return CardCheck(True, False, "unsupported agent card version")
    if card_agent != agent_id:
        return CardCheck(True, False, "agent card is for a different agent")
    if not _WALLET_RE.match(card_wallet) or card_wallet != wallet.lower():
        return CardCheck(True, False, "agent card is for a different wallet")
    if card_did != did:
        return CardCheck(True, False, "agent card was not signed by this agent's registered passkey identity")
    if expires_at <= now:
        return CardCheck(True, False, "agent card expired")
    if expires_at - now > MAX_CARD_LIFETIME_SECONDS:
        return CardCheck(True, False, "agent card lifetime exceeds 30 days")
    if not isinstance(signature, str) or not _SIG_RE.match(signature):
        return CardCheck(True, False, "malformed agent card signature")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(did[len(DID_PREFIX):]))
        key.verify(bytes.fromhex(signature), card_message(agent_id, card_wallet, expires_at))
    except (InvalidSignature, ValueError):
        return CardCheck(True, False, "invalid agent card signature")
    return CardCheck(True, True)
