"""Transaction analyzer detectors: infinite approvals, zero slippage, severity selection."""
import pytest

from guardian.web3sec.simulation import SimulationResult
from guardian.web3sec.tx_analyzer import (
    InfiniteApprovalDetector,
    TransactionAnalyzer,
    ZeroSlippageDetector,
)

SIM = SimulationResult(success=True, gas_used=50000, return_data="")
THREAT = "0x000000000000000000000000000000000000dead"
SPENDER = "000000000000000000000000" + "11" * 20
RULES = {"reserve_manipulation": True, "infinite_approval": True, "role_change": True,
         "zero_slippage": True, "threat_address": True}


def _word(n: int) -> str:
    return hex(n)[2:].rjust(64, "0")


def _approve(amount: int, selector: str = "095ea7b3") -> dict:
    return {"to": "0x" + "22" * 20, "data": "0x" + selector + SPENDER + _word(amount), "value": 0}


@pytest.fixture
def analyzer():
    return TransactionAnalyzer({"detection_rules": RULES, "threat_feed_addresses": [THREAT]})


# ── A4: all detectors run, highest severity wins ─────────────────────────────

def test_skim_to_threat_address_reports_threat_critical(analyzer):
    tx = {"to": THREAT, "data": "0xbc25cf77" + SPENDER, "value": 0}
    res = analyzer.analyze_transaction(tx, SIM)
    assert res.blocked and res.detector_name == "threat_address" and res.severity == "critical"


def test_first_detector_wins_a_severity_tie(analyzer):
    # sync() is high via reserve_manipulation; an approval hit on the same tx would tie and lose.
    res = analyzer.analyze_transaction({"to": "0x" + "22" * 20, "data": "0xfff6cae9", "value": 0}, SIM)
    assert res.detector_name == "reserve_manipulation" and res.severity == "high"


def test_no_detector_hit_returns_none(analyzer):
    assert analyzer.analyze_transaction({"to": "0x" + "22" * 20, "data": "0x1234", "value": 0}, SIM) is None


def test_live_rules_can_disable_detectors(analyzer):
    tx = {"to": THREAT, "data": "0x", "value": 0}
    assert analyzer.analyze_transaction(tx, SIM, live_rules={"threat_address": False}) is None


# ── A5: infinite approval ────────────────────────────────────────────────────

def test_uppercase_max_approval_flagged():
    tx = {"data": "0x095EA7B3" + SPENDER.upper() + "F" * 64}
    assert InfiniteApprovalDetector().analyze(tx, SIM).severity == "high"


def test_exactly_2_pow_255_flagged():
    assert InfiniteApprovalDetector().analyze(_approve(2 ** 255), SIM) is not None


def test_just_below_2_pow_255_not_flagged():
    assert InfiniteApprovalDetector().analyze(_approve(2 ** 255 - 1), SIM) is None


def test_normal_amount_not_flagged():
    assert InfiniteApprovalDetector().analyze(_approve(10 ** 18), SIM) is None


def test_increase_allowance_max_flagged():
    assert InfiniteApprovalDetector().analyze(_approve(2 ** 256 - 1, "39509351"), SIM) is not None


def test_max_hex_in_spender_slot_not_flagged():
    data = "0x095ea7b3" + "f" * 64 + _word(1)
    assert InfiniteApprovalDetector().analyze({"data": data}, SIM) is None


def test_permit2_uint160_max_flagged():
    data = "0x87517c45" + SPENDER + SPENDER + _word(2 ** 160 - 1) + _word(2 ** 48 - 1)
    assert InfiniteApprovalDetector().analyze({"data": data}, SIM) is not None


def test_permit2_small_amount_not_flagged():
    data = "0x87517c45" + SPENDER + SPENDER + _word(10 ** 18) + _word(2 ** 48 - 1)
    assert InfiniteApprovalDetector().analyze({"data": data}, SIM) is None


# ── A6: zero slippage ────────────────────────────────────────────────────────

def _swap(amount_in: int, amount_out_min: int) -> dict:
    data = ("0x38ed1739" + _word(amount_in) + _word(amount_out_min) + _word(0xa0) + SPENDER
            + _word(2 ** 32) + _word(0))
    return {"data": data}


def test_zero_amount_out_min_flagged():
    assert ZeroSlippageDetector().analyze(_swap(10 ** 18, 0), SIM).severity == "high"


def test_nonzero_amount_out_min_with_zero_elsewhere_not_flagged():
    assert ZeroSlippageDetector().analyze(_swap(10 ** 18, 5 * 10 ** 17), SIM) is None


def test_short_swap_calldata_not_flagged():
    assert ZeroSlippageDetector().analyze({"data": "0x38ed1739" + _word(1)}, SIM) is None
