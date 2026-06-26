"""
Cross-Agent Interlock Protocol — Mutual proof of agent-to-agent interaction.

When Agent A interacts with Agent B, both Cortex recorders create
a shared cryptographic proof (interlock) that neither party can deny.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("guardian.cortex.interlock")


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class InterlockProof:
    """
    A cryptographic proof that two agents interacted.

    Both agents' Cortex records include the same interlock_id and nonce,
    creating an undeniable mutual proof.
    """
    interlock_id: str
    agent_a_id: str
    agent_b_id: str
    nonce: str
    interaction_hash: str
    agent_a_event_id: str = ""
    agent_b_event_id: str = ""
    timestamp: float = 0.0
    proof_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_row(cls, row: tuple) -> "InterlockProof":
        return cls(
            interlock_id=row[0],
            agent_a_id=row[1],
            agent_b_id=row[2],
            nonce=row[3],
            interaction_hash=row[4],
            agent_a_event_id=row[5] or "",
            agent_b_event_id=row[6] or "",
            timestamp=float(row[7]),
            proof_hash=row[8] or "",
            metadata=json.loads(row[9]) if row[9] else {},
        )


class InterlockProtocol:
    """
    Manages cross-agent interlocks.

    When two agents interact, this protocol creates a shared
    cryptographic proof that binds both parties' Cortex records.
    """

    def __init__(self, db_path: str = "guardian.db"):
        self.db_path = db_path
        self._init_tables()

    def _init_tables(self) -> None:
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cortex_interlocks (
                interlock_id      TEXT PRIMARY KEY,
                agent_a_id        TEXT NOT NULL,
                agent_b_id        TEXT NOT NULL,
                nonce             TEXT NOT NULL,
                interaction_hash  TEXT NOT NULL,
                agent_a_event_id  TEXT DEFAULT '',
                agent_b_event_id  TEXT DEFAULT '',
                timestamp         REAL NOT NULL,
                proof_hash        TEXT DEFAULT '',
                metadata          TEXT DEFAULT '{}'
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_interlock_agents
            ON cortex_interlocks(agent_a_id, agent_b_id)
        """)

        conn.commit()
        conn.close()
        logger.info("Interlock tables initialized")

    def create_interlock(
        self,
        agent_a_id: str,
        agent_b_id: str,
        interaction_type: str = "request",
        interaction_data: Optional[Dict] = None,
        agent_a_event_id: str = "",
        agent_b_event_id: str = "",
    ) -> InterlockProof:
        """
        Create a mutual proof of interaction between two agents.

        The interlock contains:
        - A unique nonce (prevents replay attacks)
        - A hash of the interaction data (privacy-preserving)
        - References to both agents' Cortex event IDs
        - A proof hash binding all fields together
        """
        now = time.time()
        interlock_id = str(uuid.uuid4())
        nonce = _sha256(f"{interlock_id}:{now}:{uuid.uuid4()}")

        # Hash the interaction data (privacy-preserving)
        data_str = json.dumps(interaction_data or {}, sort_keys=True)
        interaction_hash = _sha256(
            f"{agent_a_id}:{agent_b_id}:{interaction_type}:{data_str}:{nonce}"
        )

        # Proof hash binds everything together (tamper-evident)
        proof_hash = _sha256(
            f"{interlock_id}:{agent_a_id}:{agent_b_id}:{nonce}:"
            f"{interaction_hash}:{agent_a_event_id}:{agent_b_event_id}:{now}"
        )

        proof = InterlockProof(
            interlock_id=interlock_id,
            agent_a_id=agent_a_id,
            agent_b_id=agent_b_id,
            nonce=nonce,
            interaction_hash=interaction_hash,
            agent_a_event_id=agent_a_event_id,
            agent_b_event_id=agent_b_event_id,
            timestamp=now,
            proof_hash=proof_hash,
            metadata={
                "interaction_type": interaction_type,
                "data_hash": _sha256(data_str),
            },
        )

        # Persist
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cortex_interlocks
                (interlock_id, agent_a_id, agent_b_id, nonce, interaction_hash,
                 agent_a_event_id, agent_b_event_id, timestamp, proof_hash, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof.interlock_id, proof.agent_a_id, proof.agent_b_id,
                proof.nonce, proof.interaction_hash,
                proof.agent_a_event_id, proof.agent_b_event_id,
                proof.timestamp, proof.proof_hash,
                json.dumps(proof.metadata),
            ),
        )
        conn.commit()
        conn.close()

        logger.info(
            "Interlock created: %s ↔ %s (id=%s)",
            agent_a_id, agent_b_id, interlock_id[:12],
        )
        return proof

    def verify_interlock(self, proof: InterlockProof) -> Dict[str, Any]:
        """
        Verify an interlock proof is authentic and untampered.

        Recomputes the proof hash from the fields and compares.
        Also checks that the interlock exists in the database.
        """
        # Recompute proof hash
        expected_hash = _sha256(
            f"{proof.interlock_id}:{proof.agent_a_id}:{proof.agent_b_id}:"
            f"{proof.nonce}:{proof.interaction_hash}:"
            f"{proof.agent_a_event_id}:{proof.agent_b_event_id}:{proof.timestamp}"
        )

        hash_valid = expected_hash == proof.proof_hash

        # Check DB existence
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT proof_hash FROM cortex_interlocks WHERE interlock_id = ?",
            (proof.interlock_id,),
        )
        row = cur.fetchone()
        conn.close()

        db_exists = row is not None
        db_matches = row[0] == proof.proof_hash if row else False

        return {
            "interlock_id": proof.interlock_id,
            "verified": hash_valid and db_exists and db_matches,
            "hash_valid": hash_valid,
            "db_exists": db_exists,
            "db_matches": db_matches,
            "agents": [proof.agent_a_id, proof.agent_b_id],
            "timestamp": proof.timestamp,
        }

    def get_interlocks(
        self,
        agent_id: str,
        limit: int = 50,
    ) -> List[InterlockProof]:
        """Get all interlocks involving an agent."""
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM cortex_interlocks
            WHERE agent_a_id = ? OR agent_b_id = ?
            ORDER BY timestamp DESC LIMIT ?
            """,
            (agent_id, agent_id, limit),
        )
        rows = cur.fetchall()
        conn.close()
        return [InterlockProof.from_row(r) for r in rows]

    def get_interlock(self, interlock_id: str) -> Optional[InterlockProof]:
        """Get a specific interlock by ID."""
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM cortex_interlocks WHERE interlock_id = ?",
            (interlock_id,),
        )
        row = cur.fetchone()
        conn.close()
        return InterlockProof.from_row(row) if row else None

    def _update_metadata(self, interlock_id: str, metadata: Dict[str, Any]) -> None:
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE cortex_interlocks SET metadata = ? WHERE interlock_id = ?",
            (json.dumps(metadata), interlock_id),
        )
        conn.commit()
        conn.close()

    def anchor_interlock(
        self,
        interlock_id: str,
        chain_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Anchor a registered interlock proof to the blockchain.
        """
        from pathlib import Path
        import os
        proof = self.get_interlock(interlock_id)
        if not proof:
            return {"success": False, "error": f"Interlock proof {interlock_id} not found"}

        mode = os.getenv("GUARDIAN_ANCHOR_MODE", "simulated").strip().lower()
        chain = chain_id or "monad"

        if proof.metadata.get("onchain_tx"):
            return {
                "success": True,
                "tx_hash": proof.metadata["onchain_tx"],
                "chain": proof.metadata.get("onchain_chain", chain),
                "simulated": proof.metadata.get("onchain_simulated", True),
            }

        if mode == "live":
            try:
                from web3 import Web3
                from eth_account import Account

                rpc_url = "https://testnet.monad.xyz/v1" if chain == "monad" else "https://mainnet.base.org"
                chain_id_num = 10143 if chain == "monad" else 8453

                w3 = Web3(Web3.HTTPProvider(rpc_url))
                deployer_key = os.getenv("GUARDIAN_DEPLOYER_PRIVATE_KEY", "")
                if not deployer_key:
                    raise EnvironmentError("GUARDIAN_DEPLOYER_PRIVATE_KEY not set")

                account = Account.from_key(deployer_key)

                contract_addr = os.getenv(f"GUARDIAN_INTERLOCK_CONTRACT_{chain.upper()}", "")
                if not contract_addr:
                    raise EnvironmentError(f"GUARDIAN_INTERLOCK_CONTRACT_{chain.upper()} not set")

                abi_path = Path(__file__).parent / "contracts" / "interlock_registry_abi.json"
                with open(abi_path, "r") as f:
                    abi = json.load(f)

                contract = w3.eth.contract(address=w3.to_checksum_address(contract_addr), abi=abi)

                agent_a_bytes = Web3.keccak(text=proof.agent_a_id)
                agent_b_bytes = Web3.keccak(text=proof.agent_b_id)
                proof_bytes = bytes.fromhex(proof.proof_hash)

                # Convert proof_hash to numeric nonce
                nonce_val = int(proof.proof_hash[:16], 16)

                nonce = w3.eth.get_transaction_count(account.address)
                gas_price = w3.eth.gas_price

                txn = contract.functions.registerInterlock(
                    agent_a_bytes,
                    agent_b_bytes,
                    proof_bytes,
                    nonce_val,
                ).build_transaction({
                    "from": account.address,
                    "nonce": nonce,
                    "gas": 250_000,
                    "gasPrice": gas_price,
                    "chainId": chain_id_num,
                })

                signed = w3.eth.account.sign_transaction(txn, deployer_key)
                tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction).hex()

                w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

                proof.metadata["onchain_tx"] = tx_hash
                proof.metadata["onchain_chain"] = chain
                proof.metadata["onchain_simulated"] = False

                self._update_metadata(interlock_id, proof.metadata)
                return {
                    "success": True,
                    "tx_hash": tx_hash,
                    "chain": chain,
                    "simulated": False,
                }
            except Exception as e:
                logger.exception("Failed to anchor interlock live")
                return {"success": False, "error": str(e)}
        else:
            mock_tx = f"0x{hashlib.sha256(f'interlock-{interlock_id}'.encode()).hexdigest()}"
            proof.metadata["onchain_tx"] = mock_tx
            proof.metadata["onchain_chain"] = chain
            proof.metadata["onchain_simulated"] = True

            self._update_metadata(interlock_id, proof.metadata)
            return {
                "success": True,
                "tx_hash": mock_tx,
                "chain": chain,
                "simulated": True,
            }
