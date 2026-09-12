from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import time

import requests

from guardian.onchain_safety import OwnershipNotTransferredError

logger = logging.getLogger("guardian.audit.onchain_risk_scorer")


@dataclass
class OnChainRiskScore:
    chain: str
    contract_address: str
    score: float
    grade: str
    signals: Dict[str, Any]
    risk_summary: Dict[str, int]


class OnChainRiskScorer:
    """
    Lightweight on-chain risk scorer for launch chains.
    Supports EVM launch targets (Ethereum, BSC, Monad-like EVM endpoints).
    """

    _CHAIN_APIS: Dict[str, Dict[str, Any]] = {
        "ethereum": {"chain_id": 1, "legacy_api": "https://api.etherscan.io/api"},
        "eth": {"chain_id": 1, "legacy_api": "https://api.etherscan.io/api"},
        "bsc": {"chain_id": 56, "legacy_api": "https://api.bscscan.com/api"},
        "monad": {"chain_id": 10143, "legacy_api": "https://api.monadscan.com/api"},
    }

    def _grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def _build_explorer_urls(self, chain: str, address: str) -> List[str]:
        info = self._CHAIN_APIS.get(chain, {})
        urls: List[str] = []
        chain_id = info.get("chain_id")
        if chain_id:
            urls.append(
                f"https://api.etherscan.io/v2/api?chainid={chain_id}"
                f"&module=contract&action=getsourcecode&address={address}"
            )
        legacy = info.get("legacy_api")
        if legacy:
            urls.append(
                f"{legacy}?module=contract&action=getsourcecode&address={address}"
            )
        return urls

    def _fetch_verification_signal(self, chain: str, address: str, api_key: Optional[str]) -> Dict[str, Any]:
        headers = {"X-Api-Key": api_key} if api_key else {}
        for url in self._build_explorer_urls(chain, address):
            try:
                resp = requests.get(url, headers=headers, timeout=12)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                result = data.get("result")
                if isinstance(result, list) and result:
                    row = result[0] if isinstance(result[0], dict) else {}
                    src = str(row.get("SourceCode", "") or "")
                    verified = bool(src.strip())
                    proxy = str(row.get("Proxy", "0")) == "1"
                    return {
                        "source_verified": verified,
                        "unverified_proxy": proxy and not verified,
                        "proxy": proxy,
                    }
            except Exception:
                continue
            finally:
                time.sleep(0.25)
        return {"source_verified": False, "unverified_proxy": False, "proxy": False}

    def _fetch_contract_age_days(self, chain: str, address: str, api_key: Optional[str]) -> Optional[float]:
        """Fetch contract age by looking up first transaction timestamp."""
        info = self._CHAIN_APIS.get(chain, {})
        legacy = info.get("legacy_api")
        if not legacy:
            return None
        url = (
            f"{legacy}?module=account&action=txlist&address={address}"
            f"&startblock=0&endblock=99999999&page=1&offset=1&sort=asc"
        )
        headers = {"X-Api-Key": api_key} if api_key else {}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                txs = data.get("result")
                if isinstance(txs, list) and txs:
                    ts = int(str(txs[0].get("timeStamp", "0") or "0"))
                    if ts > 0:
                        return (time.time() - ts) / 86400.0
        except Exception as exc:
            logger.debug("Failed to fetch contract age for %s: %s", address, exc)
        return None

    def _fetch_tx_count(self, chain: str, address: str, api_key: Optional[str]) -> Optional[int]:
        """Fetch transaction count for a contract address."""
        info = self._CHAIN_APIS.get(chain, {})
        legacy = info.get("legacy_api")
        if not legacy:
            return None
        url = (
            f"{legacy}?module=proxy&action=eth_getTransactionCount"
            f"&address={address}&tag=latest"
        )
        headers = {"X-Api-Key": api_key} if api_key else {}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                result = data.get("result", "0x0")
                if isinstance(result, str) and result.startswith("0x"):
                    return int(result, 16)
        except Exception as exc:
            logger.debug("Failed to fetch tx count for %s: %s", address, exc)
        return None

    def score_contract(self, chain: str, contract_address: str, api_key: Optional[str] = None) -> OnChainRiskScore:
        chain_key = (chain or "").strip().lower()
        if chain_key in {"sol", "solana"}:
            signals = {
                "source_verified": False,
                "note": "Solana scoring requires program-account specific adapters.",
            }
            return OnChainRiskScore(
                chain=chain_key,
                contract_address=contract_address,
                score=65.0,
                grade="D",
                signals=signals,
                risk_summary={"critical": 0, "high": 1, "medium": 1, "low": 0},
            )

        address = contract_address.strip().lower()
        if not address.startswith("0x") or len(address) != 42:
            raise ValueError(f"Invalid EVM contract address: {contract_address}")

        verification = self._fetch_verification_signal(chain_key, address, api_key)
        score = 100.0
        critical = 0
        high = 0
        medium = 0
        low = 0

        # Signal 1: Source verification (existing)
        if not verification["source_verified"]:
            score -= 30
            critical += 1
        # Signal 2: Unverified proxy (existing)
        if verification["unverified_proxy"]:
            score -= 20
            critical += 1

        # Signal 3: Contract age — contracts < 7 days old are high risk
        age_days = self._fetch_contract_age_days(chain_key, address, api_key)
        if age_days is not None:
            if age_days < 7:
                score -= 15
                high += 1
            elif age_days < 30:
                score -= 5
                medium += 1
        else:
            # Unknown age is a mild concern
            medium += 1

        # Signal 4: Transaction count — very low activity is suspicious
        tx_count = self._fetch_tx_count(chain_key, address, api_key)
        if tx_count is not None:
            if tx_count < 10:
                score -= 15
                high += 1
            elif tx_count < 100:
                score -= 10
                medium += 1

        # Signals 5-7 are reported as "unknown" when no data available.
        # Full implementation requires DEX subgraph or token analytics API.
        holder_concentration = "unknown"
        liquidity_usd = "unknown"
        approval_count = "unknown"

        signals: Dict[str, Any] = {
            **verification,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "contract_age_days": f"{age_days:.2f}" if age_days is not None else "unknown",
            "tx_count": tx_count if tx_count is not None else "unknown",
            "holder_concentration_top10": holder_concentration,
            "liquidity_usd": liquidity_usd,
            "approval_count": approval_count,
        }

        score = max(0.0, round(score, 1))
        return OnChainRiskScore(
            chain=chain_key,
            contract_address=address,
            score=score,
            grade=self._grade(score),
            signals=signals,
            risk_summary={
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
        )

    def attest_to_chain(self, risk_score: OnChainRiskScore, chain_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Attest contract risk score and grade on-chain.
        """
        import os
        import json
        import hashlib
        from pathlib import Path

        mode = os.getenv("GUARDIAN_ANCHOR_MODE", "simulated").strip().lower()
        chain = chain_id or risk_score.chain

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

                contract_addr = os.getenv(f"GUARDIAN_RISK_CONTRACT_{chain.upper()}", "")
                if not contract_addr:
                    raise EnvironmentError(f"GUARDIAN_RISK_CONTRACT_{chain.upper()} not set")

                abi_path = Path(__file__).parent / "contracts" / "risk_attestation_abi.json"
                with open(abi_path, "r") as f:
                    abi = json.load(f)

                contract = w3.eth.contract(address=w3.to_checksum_address(contract_addr), abi=abi)

                signals_str = json.dumps(risk_score.signals, sort_keys=True)
                signals_hash = hashlib.sha256(signals_str.encode()).digest()

                nonce = w3.eth.get_transaction_count(account.address)
                gas_price = w3.eth.gas_price

                # Score is scaled or float to int
                score_val = int(risk_score.score)

                txn = contract.functions.attest(
                    w3.to_checksum_address(risk_score.contract_address),
                    chain,
                    score_val,
                    risk_score.grade,
                    signals_hash
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

                return {"success": True, "tx_hash": tx_hash, "chain": chain, "simulated": False}
            except OwnershipNotTransferredError:
                raise  # Safety checks must never be silently swallowed
            except Exception as e:
                import logging
                logging.getLogger("guardian.audit.onchain_risk_scorer").exception("Failed to attest risk on-chain")
                return {"success": False, "error": str(e)}
        else:
            mock_tx = f"0x{hashlib.sha256(f'risk-{risk_score.contract_address}-{chain}'.encode()).hexdigest()}"
            return {"success": True, "tx_hash": mock_tx, "chain": chain, "simulated": True}
