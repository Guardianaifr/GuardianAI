"""Canonical agent id: every spelling of an agent maps to one bytes32 hex string.

A raw name ("payroll"), its keccak hash, and the bytes32 form must all resolve to the same agent, so
per-agent rules, daily caps and passkey cards cannot be dodged by changing how the id is written.
"""
from __future__ import annotations

import re
from typing import Union

from web3 import Web3

_BYTES32_HEX = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _keccak_hex(text: str) -> str:
    h = Web3.keccak(text=text).hex().lower()
    return h if h.startswith("0x") else "0x" + h


def normalize_agent_id(agent_id: Union[str, bytes]) -> str:
    """bytes32 hex (lowercase). A 0x+64 string is used as-is only when it is all hex, else it is hashed."""
    if isinstance(agent_id, (bytes, bytearray)):
        return "0x" + bytes(agent_id).hex().rjust(64, "0")[:64]
    if isinstance(agent_id, str):
        if _BYTES32_HEX.match(agent_id):
            return agent_id.lower()
        return _keccak_hex(agent_id)
    return _keccak_hex(str(agent_id))
