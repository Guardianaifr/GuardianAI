import os
import tempfile
from typing import Dict, List, Set, Any
import logging

try:
    from slither.slither import Slither
    from slither.exceptions import SlitherError
    from crytic_compile.crytic_compile import CryticCompile
except ImportError:
    Slither = None

from .slither_detectors import CUSTOM_DETECTORS

logger = logging.getLogger(__name__)

# Map from Guardian rule ID to a list of Slither detector names
SLITHER_BUILTIN_MAP = {
    "SC-001": ["reentrancy-benign", "reentrancy-eth", "reentrancy-no-eth", "reentrancy-unlimited-gas", "reentrancy-events"],
    "SC-041": ["controlled-delegatecall", "delegatecall-loop"],
    "SC-020": ["divide-before-multiply", "solc-version"], # we will filter solc-version for < 0.8
    "SC-030": ["tx-origin"],
    "SC-042": ["suicidal"],
    # SC-050 intentionally NOT in this map — Slither's built-in "timestamp" detector is
    # too broad (flags cosmetic block.timestamp uses).  The custom TimestampDetector in
    # slither_detectors.py handles SC-050 with security-critical-impact filtering.
    "SC-113": ["read-only-reentrancy"],
    "SC-112": ["proxy-bug"],
}

# Map from custom detector ARGUMENT to Guardian rule ID
CUSTOM_MAP = {
    "guardian-access-control": "SC-031",
    "guardian-unprotected-init": "SC-119",
    "guardian-uncapped-mint": "SC-102",
    "guardian-flash-loan": "SC-060",
    "guardian-signature-replay": "SC-111",
    "guardian-governance-attack": "SC-116",
    "guardian-mev-sandwich": "SC-114",
    "guardian-no-timelock": "SC-101",
    "guardian-oracle-centralization": "SC-122",
    "guardian-reentrancy": "SC-001",
    "guardian-delegatecall": "SC-041",
    "guardian-integer-overflow": "SC-020",
    "guardian-tx-origin": "SC-030",
    "guardian-selfdestruct": "SC-042",
    "guardian-timestamp": "SC-050",
    "guardian-unverified-proxy": "SC-105",
    "guardian-read-only-reentrancy": "SC-113",
    "guardian-storage-collision": "SC-112",
    "guardian-no-reentrancy-guard": "SC-002",
    "guardian-front-running": "SC-010",
    "guardian-missing-slippage": "SC-011",
    "guardian-spot-price-oracle": "SC-061",
    "guardian-single-eoa-admin": "SC-100",
    "guardian-admin-mint": "SC-103",
    "guardian-instant-role": "SC-104",
    "guardian-collateral-freshness": "SC-106",
    "guardian-role-monitor": "SC-107",
    "guardian-bridge-replay": "SC-110",
    "guardian-unchecked-arithmetic": "SC-021",
    "guardian-default-visibility": "SC-032",
    "guardian-missing-deadline": "SC-115",
    "guardian-donation-attack": "SC-117",
    "guardian-missing-zero": "SC-118",
    "guardian-missing-event": "SC-121",
    "guardian-permit-phishing": "SC-123",
    "guardian-reward-rounding": "SC-124",
    "guardian-non-constant-state": "SC-132",
    "guardian-phantom-call": "SC-130",
    "guardian-magic-number": "SC-133"
}

def run_slither_analysis(source_code: str) -> Dict[str, List[str]]:
    """
    Runs Slither on the source code and maps results back to Guardian rule IDs.
    Returns a dict mapping Rule ID -> list of snippet strings.
    If Slither fails (e.g. compilation error), returns None.
    """
    if Slither is None:
        logger.warning("Slither is not installed.")
        return None

    # Write source code to temp file
    fd, temp_path = tempfile.mkstemp(suffix=".sol")
    os.close(fd)
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(source_code)
        
        try:
            slither = Slither(temp_path)
            # Register custom detectors
            for detector in CUSTOM_DETECTORS:
                slither.register_detector(detector)
            
            slither.run_detectors()
            
            findings = {}
            for d in slither.detectors:
                # Built-in matching
                for rule_id, slither_names in SLITHER_BUILTIN_MAP.items():
                    if d.ARGUMENT in slither_names:
                        # For SC-020 (overflow), only report if solc-version is <0.8 or divide-before-multiply
                        if rule_id == "SC-020" and d.ARGUMENT == "solc-version":
                            # Slither's solc-version reports if < 0.8.0, but wait, it reports on ^0.8.20 too for other reasons
                            # Let's handle SC-020 specially if needed, or rely on our regex fallback if we skip it here.
                            # Actually, let's just use Slither's divide-before-multiply for SC-020 and let regex handle the solc version.
                            if d.ARGUMENT == "solc-version":
                                continue

                        if rule_id not in findings:
                            findings[rule_id] = []
                        
                        # Collect results
                        try:
                            # d.results might be populated? Or we have to call detect()
                            results = d.detect()
                            if results:
                                findings[rule_id].append(d.ARGUMENT)
                        except Exception as e:
                            pass
                # Custom matching
                if d.ARGUMENT in CUSTOM_MAP:
                    rule_id = CUSTOM_MAP[d.ARGUMENT]
                    if rule_id not in findings:
                        findings[rule_id] = []
                    try:
                        if getattr(d, 'guardian_findings', []):
                            findings[rule_id].extend(d.guardian_findings)
                    except Exception as e:
                        pass
            
            return findings

        except Exception as e:
            logger.debug(f"Slither analysis failed: {e}")
            return None
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
