
"""
audit_identity_drift.py � read-only reconciliation check.

For every CONFIRMED ERC-8004 registration, compares:
  - erc8004_registrations.owner_address  (what we think we handed off to)
  - the real on-chain ownerOf(token_id)  (who actually holds the NFT now)
  - agent_passports.owner_pubkey         (what the RPC relay's address-based
                                           lookup will actually match against)

Reports every mismatch. Changes nothing � this is a diagnostic, not a fix.
Run this BEFORE enabling GUARDIAN_IDENTITY_GATE_ONCHAIN_VERIFY or MODE=enforce
anywhere that matters, and periodically afterward (ownership can drift again
any time an operator transfers a token outside this system's own workflow).

Usage:
    python3 audit_identity_drift.py [--chain base-sepolia] [--db guardian.db]

Exit code: 0 if no drift found, 1 if any mismatch found (so this can be used
as a CI/cron gate � e.g. refuse to flip enforce mode on if this fails).
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
import os

from dotenv import load_dotenv
load_dotenv(".env")

from guardian.passport.erc8004_registrar import (
    IDENTITY_REGISTRY_ABI,
    _resolve_chain_config,
)


def fetch_confirmed_registrations(db_path: str, chain: str):
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT r.agent_id, r.token_id, r.owner_address,
                   p.owner_pubkey, p.tier, p.is_active
            FROM erc8004_registrations r
            LEFT JOIN agent_passports p ON p.agent_id = r.agent_id
            WHERE r.chain = ? AND r.status = 'confirmed' AND r.token_id IS NOT NULL
            ORDER BY r.agent_id
            """,
            (chain,),
        )
        return cur.fetchall()
    finally:
        conn.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="base-sepolia")
    ap.add_argument("--db", default="guardian.db")
    args = ap.parse_args()

    from web3 import Web3

    cfg = _resolve_chain_config(args.chain)
    w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(cfg["registry"]), abi=IDENTITY_REGISTRY_ABI
    )

    rows = fetch_confirmed_registrations(args.db, args.chain)
    if not rows:
        print(f"No confirmed registrations found for chain={args.chain} in {args.db}.")
        return 0

    print(f"Auditing {len(rows)} confirmed registration(s) on {args.chain}...\n")
    drift_count = 0
    error_count = 0

    for agent_id, token_id, stored_owner_address, owner_pubkey, tier, is_active in rows:
        try:
            onchain_owner = contract.functions.ownerOf(int(token_id)).call()
        except Exception as exc:  # noqa: BLE001
            error_count += 1
            print(f"[ERROR]  {agent_id} (tokenId={token_id}): ownerOf() failed: {exc}")
            continue

        onchain_owner_l = onchain_owner.lower()
        stored_l = (stored_owner_address or "").lower()
        pubkey_l = (owner_pubkey or "").lower()

        registration_drift = stored_l != onchain_owner_l
        relay_drift = pubkey_l != onchain_owner_l  # what actually matters for the RPC relay lookup

        if not registration_drift and not relay_drift:
            print(f"[OK]     {agent_id} (tokenId={token_id}): on-chain owner matches both local records")
            continue

        drift_count += 1
        print(f"[DRIFT]  {agent_id} (tokenId={token_id}) tier={tier} active={bool(is_active)}")
        print(f"           on-chain ownerOf():        {onchain_owner}")
        print(f"           erc8004_registrations:      {stored_owner_address!r}"
              f"{'  <-- MISMATCH' if registration_drift else '  (matches)'}")
        print(f"           agent_passports.owner_pubkey:{owner_pubkey!r}"
              f"{'  <-- MISMATCH (relay lookup will fail for the real owner)' if relay_drift else '  (matches)'}")
        print()

    print(f"\n{len(rows)} checked, {drift_count} with drift, {error_count} RPC error(s).")
    if drift_count:
        print(
            "\nFix: UPDATE agent_passports SET owner_pubkey = <onchain ownerOf() address> "
            "WHERE agent_id = <agent_id>; then re-verify with this script before enabling enforce mode."
        )
    return 1 if drift_count else 0


if __name__ == "__main__":
    sys.exit(main())

