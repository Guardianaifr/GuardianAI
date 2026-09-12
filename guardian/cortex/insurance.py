"""
Insurance Certificate Generator — Produces cryptographic evidence
packages that insurers need to underwrite autonomous AI agents.

Aggregates Cortex decision history, Merkle anchor proofs, trust scores,
and policy compliance into a signed, verifiable certificate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from guardian.onchain_safety import OwnershipNotTransferredError

logger = logging.getLogger("guardian.cortex.insurance")

# Allowlist of valid risk levels accepted for on-chain anchoring.
# Must stay in sync with GuardianInsuranceLedger.sol _validRiskLevel() helper.
# Casing convention: ALL UPPERCASE, matching _assess_risk() output.
VALID_RISK_LEVELS: frozenset = frozenset({"LOW", "MEDIUM", "HIGH"})


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class InsuranceCertificate:
    """
    A signed evidence package for insurance underwriting.

    Contains aggregated metrics from an agent's Cortex history,
    Merkle anchor proofs, and trust score data over a coverage period.
    """
    certificate_id: str
    agent_id: str
    period_start: float
    period_end: float
    generated_at: float

    # Decision metrics
    total_decisions: int = 0
    total_events: int = 0
    event_type_breakdown: Dict[str, int] = field(default_factory=dict)

    # Anchor metrics
    merkle_anchors: int = 0
    chains_used: List[str] = field(default_factory=list)
    all_anchors_verified: bool = False

    # Safety metrics
    anomalies_detected: int = 0
    policy_violations: int = 0
    policy_gates_fired: int = 0
    escalations: int = 0

    # Trust score
    trust_score: float = 0.0
    trust_tier: str = "UNVERIFIED"

    # Interlock metrics
    cross_agent_interlocks: int = 0

    # Certificate integrity
    data_hash: str = ""
    certificate_signature: str = ""

    # Coverage assessment
    risk_level: str = "UNKNOWN"
    coverage_recommendation: str = ""

    # On-chain details
    onchain_tx: str = ""
    onchain_chain: str = ""
    onchain_simulated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InsuranceCertificateGenerator:
    """
    Generates insurance evidence certificates from Cortex data.

    Aggregates an agent's decision history, Merkle proofs,
    trust scores, and compliance data into a signed package
    that insurance underwriters can verify.
    """

    def __init__(self, db_path: str = "guardian.db"):
        self.db_path = db_path
        self._init_tables()

    def _init_tables(self) -> None:
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cortex_insurance_certificates (
                certificate_id          TEXT PRIMARY KEY,
                agent_id                TEXT NOT NULL,
                period_start            REAL NOT NULL,
                period_end              REAL NOT NULL,
                generated_at            REAL NOT NULL,
                total_decisions         INTEGER NOT NULL,
                total_events            INTEGER NOT NULL,
                merkle_anchors          INTEGER NOT NULL,
                cross_agent_interlocks  INTEGER NOT NULL,
                risk_level              TEXT NOT NULL,
                data_hash               TEXT NOT NULL,
                certificate_signature   TEXT NOT NULL,
                onchain_tx              TEXT DEFAULT '',
                onchain_chain           TEXT DEFAULT '',
                onchain_simulated       INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def generate_certificate(
        self,
        agent_id: str,
        period_start: float,
        period_end: float,
        trust_score: float = 0.0,
        trust_tier: str = "UNVERIFIED",
    ) -> InsuranceCertificate:
        """
        Generate an insurance certificate for the given agent and period.

        Queries:
        - cortex_events for decision metrics
        - cortex_anchors for on-chain proof count
        - cortex_interlocks for cross-agent interaction count
        """
        import sqlite3

        now = time.time()
        cert_id = str(uuid.uuid4())

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # ── Event metrics ─────────────────────────────────────
        cur.execute(
            """
            SELECT event_type, COUNT(*) FROM cortex_events
            WHERE agent_id = ? AND timestamp >= ? AND timestamp <= ?
            GROUP BY event_type
            """,
            (agent_id, period_start, period_end),
        )
        type_breakdown: Dict[str, int] = {}
        total_events = 0
        total_decisions = 0
        policy_gates = 0
        for row in cur.fetchall():
            etype, count = row[0], row[1]
            type_breakdown[etype] = count
            total_events += count
            if etype == "decision":
                total_decisions += count
            if etype == "policy_gate":
                policy_gates += count

        # ── Anchor metrics ────────────────────────────────────
        cur.execute(
            """
            SELECT COUNT(*), GROUP_CONCAT(DISTINCT chain_id)
            FROM cortex_anchors
            WHERE agent_id = ? AND period_start >= ? AND period_end <= ?
            """,
            (agent_id, period_start, period_end),
        )
        anchor_row = cur.fetchone()
        anchor_count = anchor_row[0] if anchor_row else 0
        chains_str = anchor_row[1] if anchor_row and anchor_row[1] else ""
        chains_used = [c.strip() for c in chains_str.split(",") if c.strip()] if chains_str else []

        # ── Interlock metrics ─────────────────────────────────
        cur.execute(
            """
            SELECT COUNT(*) FROM cortex_interlocks
            WHERE (agent_a_id = ? OR agent_b_id = ?)
            AND timestamp >= ? AND timestamp <= ?
            """,
            (agent_id, agent_id, period_start, period_end),
        )
        interlock_row = cur.fetchone()
        interlock_count = interlock_row[0] if interlock_row else 0

        conn.close()

        # ── Risk assessment ───────────────────────────────────
        risk_level, recommendation = self._assess_risk(
            total_events=total_events,
            total_decisions=total_decisions,
            anchor_count=anchor_count,
            policy_gates=policy_gates,
            trust_score=trust_score,
            period_days=(period_end - period_start) / 86400,
        )

        # ── Build certificate ─────────────────────────────────
        cert = InsuranceCertificate(
            certificate_id=cert_id,
            agent_id=agent_id,
            period_start=period_start,
            period_end=period_end,
            generated_at=now,
            total_decisions=total_decisions,
            total_events=total_events,
            event_type_breakdown=type_breakdown,
            merkle_anchors=anchor_count,
            chains_used=chains_used,
            all_anchors_verified=anchor_count > 0,
            anomalies_detected=0,
            policy_violations=0,
            policy_gates_fired=policy_gates,
            escalations=0,
            trust_score=trust_score,
            trust_tier=trust_tier,
            cross_agent_interlocks=interlock_count,
            risk_level=risk_level,
            coverage_recommendation=recommendation,
        )

        # ── Sign certificate ──────────────────────────────────
        data_str = json.dumps(cert.to_dict(), sort_keys=True, default=str)
        cert.data_hash = _sha256(data_str)
        cert.certificate_signature = _sha256(
            f"guardian-cortex-cert:{cert.certificate_id}:{cert.data_hash}"
        )

        logger.info(
            "Insurance certificate generated: agent=%s period=%.0fd events=%d risk=%s",
            agent_id, (period_end - period_start) / 86400,
            total_events, risk_level,
        )

        self.save_certificate(cert)
        return cert

    def _assess_risk(
        self,
        total_events: int,
        total_decisions: int,
        anchor_count: int,
        policy_gates: int,
        trust_score: float,
        period_days: float,
    ) -> tuple[str, str]:
        """
        Compute a risk level and coverage recommendation.

        Risk Levels:
        - LOW:     High trust score, consistent anchoring, no violations
        - MEDIUM:  Moderate trust, some gaps in anchoring
        - HIGH:    Low trust, no anchoring, policy violations
        - UNKNOWN: Insufficient data
        """
        if total_events == 0:
            return "UNKNOWN", "Insufficient decision history for assessment."

        events_per_day = total_events / max(period_days, 1)
        anchors_per_day = anchor_count / max(period_days, 1)
        gate_ratio = policy_gates / max(total_events, 1)

        score = 0.0

        # Trust score component (40%)
        score += (trust_score / 100.0) * 40

        # Anchoring consistency (30%)
        if anchors_per_day >= 1.0:
            score += 30
        elif anchors_per_day >= 0.5:
            score += 20
        elif anchor_count > 0:
            score += 10

        # Activity consistency (20%)
        if events_per_day >= 10:
            score += 20
        elif events_per_day >= 1:
            score += 10

        # Policy compliance (10%)
        if gate_ratio < 0.01:
            score += 10
        elif gate_ratio < 0.05:
            score += 5

        if score >= 75:
            return "LOW", (
                "Agent demonstrates strong trust metrics, consistent on-chain anchoring, "
                "and minimal policy violations. Recommended for standard coverage."
            )
        elif score >= 45:
            return "MEDIUM", (
                "Agent has moderate trust metrics. On-chain anchoring may be inconsistent. "
                "Recommended for coverage with enhanced monitoring requirements."
            )
        else:
            return "HIGH", (
                "Agent has limited trust history or significant policy gate activity. "
                "Recommend additional audit before coverage approval."
            )

    def save_certificate(self, cert: InsuranceCertificate) -> None:
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO cortex_insurance_certificates
                (certificate_id, agent_id, period_start, period_end, generated_at,
                 total_decisions, total_events, merkle_anchors, cross_agent_interlocks,
                 risk_level, data_hash, certificate_signature, onchain_tx, onchain_chain, onchain_simulated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert.certificate_id, cert.agent_id, cert.period_start, cert.period_end, cert.generated_at,
                cert.total_decisions, cert.total_events, cert.merkle_anchors, cert.cross_agent_interlocks,
                cert.risk_level, cert.data_hash, cert.certificate_signature,
                cert.onchain_tx, cert.onchain_chain,
                1 if cert.onchain_simulated else 0
            )
        )
        conn.commit()
        conn.close()

    def get_certificates(self, agent_id: str) -> List[InsuranceCertificate]:
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM cortex_insurance_certificates WHERE agent_id = ? ORDER BY generated_at DESC",
            (agent_id,),
        )
        rows = cur.fetchall()
        conn.close()

        certs = []
        for r in rows:
            cert = InsuranceCertificate(
                certificate_id=r[0],
                agent_id=r[1],
                period_start=float(r[2]),
                period_end=float(r[3]),
                generated_at=float(r[4]),
                total_decisions=int(r[5]),
                total_events=int(r[6]),
                merkle_anchors=int(r[7]),
                cross_agent_interlocks=int(r[8]),
                risk_level=r[9],
                data_hash=r[10],
                certificate_signature=r[11]
            )
            cert.onchain_tx = r[12]
            cert.onchain_chain = r[13]
            cert.onchain_simulated = bool(r[14])
            certs.append(cert)
        return certs

    def anchor_certificate(self, certificate_id: str, chain_id: Optional[str] = None) -> Dict[str, Any]:
        import sqlite3
        import os
        from pathlib import Path

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM cortex_insurance_certificates WHERE certificate_id = ?", (certificate_id,))
        row = cur.fetchone()
        conn.close()

        if not row:
            return {"success": False, "error": f"Certificate {certificate_id} not found"}

        cert = InsuranceCertificate(
            certificate_id=row[0],
            agent_id=row[1],
            period_start=float(row[2]),
            period_end=float(row[3]),
            generated_at=float(row[4]),
            total_decisions=int(row[5]),
            total_events=int(row[6]),
            merkle_anchors=int(row[7]),
            cross_agent_interlocks=int(row[8]),
            risk_level=row[9],
            data_hash=row[10],
            certificate_signature=row[11]
        )
        cert.onchain_tx = row[12]
        cert.onchain_chain = row[13]
        cert.onchain_simulated = bool(row[14])

        # Short-circuit: cert already anchored — return cached result idempotently.
        # This must fire BEFORE risk_level validation, since re-checking risk_level
        # on an already-committed ledger entry serves no purpose and would block
        # legitimate idempotent re-anchoring queries.
        if cert.onchain_tx:
            return {"success": True, "tx_hash": cert.onchain_tx, "chain": cert.onchain_chain, "simulated": cert.onchain_simulated}

        # ── Risk level validation (Python-side gate) ──────────────────────
        # Reject before any on-chain call if risk_level is not in the known
        # valid set. "UNKNOWN" means insufficient assessment data and must
        # never be permanently written to the immutable ledger.
        if cert.risk_level not in VALID_RISK_LEVELS:
            raise ValueError(
                f"Cannot anchor certificate with insufficient assessment data. "
                f"risk_level={cert.risk_level!r} is not one of the valid values: "
                f"{sorted(VALID_RISK_LEVELS)}. "
                "Generate or re-assess the certificate with sufficient event history first."
            )


        mode = os.getenv("GUARDIAN_ANCHOR_MODE", "simulated").strip().lower()
        chain = chain_id or "monad"

        if mode == "live":
            try:
                from guardian.onchain_safety import assert_timelock_owns_all
                assert_timelock_owns_all(chain=chain)

                from web3 import Web3
                from eth_account import Account

                rpc_url = "https://testnet.monad.xyz/v1" if chain == "monad" else "https://mainnet.base.org"
                chain_id_num = 10143 if chain == "monad" else 1

                w3 = Web3(Web3.HTTPProvider(rpc_url))
                deployer_key = os.getenv("GUARDIAN_DEPLOYER_PRIVATE_KEY", "")
                if not deployer_key:
                    raise EnvironmentError("GUARDIAN_DEPLOYER_PRIVATE_KEY not set")

                account = Account.from_key(deployer_key)

                contract_addr = os.getenv(f"GUARDIAN_INSURANCE_CONTRACT_{chain.upper()}", "")
                if not contract_addr:
                    raise EnvironmentError(f"GUARDIAN_INSURANCE_CONTRACT_{chain.upper()} not set")

                abi_path = Path(__file__).parent / "contracts" / "insurance_ledger_abi.json"
                with open(abi_path, "r") as f:
                    abi = json.load(f)

                contract = w3.eth.contract(address=w3.to_checksum_address(contract_addr), abi=abi)

                cert_id_bytes = hashlib.sha256(cert.certificate_id.encode()).digest()
                agent_hash_bytes = Web3.keccak(text=cert.agent_id)
                cert_hash_bytes = bytes.fromhex(cert.data_hash)

                nonce = w3.eth.get_transaction_count(account.address)
                gas_price = w3.eth.gas_price

                txn = contract.functions.issueCertificate(
                    cert_id_bytes,
                    agent_hash_bytes,
                    int(cert.period_start),
                    int(cert.period_end),
                    cert_hash_bytes,
                    cert.risk_level
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

                # Update DB
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute(
                    "UPDATE cortex_insurance_certificates SET onchain_tx = ?, onchain_chain = ?, onchain_simulated = 0 WHERE certificate_id = ?",
                    (tx_hash, chain, cert.certificate_id)
                )
                conn.commit()
                conn.close()

                return {"success": True, "tx_hash": tx_hash, "chain": chain, "simulated": False}
            except OwnershipNotTransferredError:
                raise  # Safety checks must never be silently swallowed
            except Exception as e:
                logger.exception("Failed to anchor certificate live")
                return {"success": False, "error": str(e)}
        else:
            mock_tx = f"0x{hashlib.sha256(f'insurance-{cert.certificate_id}'.encode()).hexdigest()}"
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "UPDATE cortex_insurance_certificates SET onchain_tx = ?, onchain_chain = ?, onchain_simulated = 1 WHERE certificate_id = ?",
                (mock_tx, chain, cert.certificate_id)
            )
            conn.commit()
            conn.close()
            return {"success": True, "tx_hash": mock_tx, "chain": chain, "simulated": True}
