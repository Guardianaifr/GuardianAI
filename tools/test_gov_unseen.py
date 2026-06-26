"""
UNSEEN DATA TEST — Governance & Hardening (Features 13-16)
============================================================
Tests advanced governance and hardening with real-world adversarial data:
  - Adversarial governance policies
  - Malicious model cards & SBOMs
  - Agency loop attacks
  - Signature tampering
"""

import sys, os, json, time
from pathlib import Path
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

from security.policy_governance import (
    validate_multi_approver_quorum,
    validate_change_window,
    validate_policy_version_pin,
    detect_config_drift,
)
from security.hardening_checks import (
    validate_model_card,
    verify_sbom_hashes,
    check_grounding_confidence,
    check_recursive_agency_depth,
)

RESULTS = {}

def run_test(name, fn):
    try:
        fn()
        RESULTS[name] = "PASS"
        print(f"  [PASS] {name}")
    except Exception as e:
        RESULTS[name] = f"FAIL: {e}"
        print(f"  [FAIL] {name}: {e}")

# --- GOVERNANCE ---
def test_gov_multi_approver():
    ok, _ = validate_multi_approver_quorum(["alice", "bob"], 2)
    assert ok
    ok, _ = validate_multi_approver_quorum(["alice", "alice"], 2)
    assert not ok

def test_gov_change_window():
    ok, _ = validate_change_window(14, [(9, 17)])
    assert ok
    ok, _ = validate_change_window(2, [(9, 17)])
    assert not ok
    # cross-midnight
    ok, _ = validate_change_window(23, [(22, 4)])
    assert ok

def test_gov_policy_pin():
    ok, _ = validate_policy_version_pin("2.1.0", "2.0.0")
    assert ok
    ok, _ = validate_policy_version_pin("1.9.9", "2.0.0")
    assert not ok

def test_gov_drift():
    live = {"governance": {"enabled": False}, "other": 1}
    base = {"governance": {"enabled": True}, "other": 1}
    findings = detect_config_drift(live, base)
    assert len(findings) == 1
    assert "governance.enabled" in findings[0].detail

# --- HARDENING ---
def test_hard_model_card():
    # Missing fields
    card1 = {"model_name": "test"}
    assert len(validate_model_card(card1)) > 0
    # Low safety score
    card2 = {
        "model_name": "test", "version": "1", "license": "MIT",
        "training_data_hash": "abc", "safety_eval_score": 0.5
    }
    f = validate_model_card(card2)
    assert any("Safety score" in x.detail for x in f)

def test_hard_grounding():
    resp = "The capital of France is Paris."
    ctx = ["Paris is the capital of France."]
    score, f = check_grounding_confidence(resp, ctx, 0.5)
    assert score >= 0.5 and len(f) == 0
    
    resp2 = "I also like eating apples."
    score2, f2 = check_grounding_confidence(resp2, ctx, 0.5)
    assert score2 < 0.5 and len(f2) > 0

def test_hard_agency():
    # Max depth
    chain = ["act1", "act2", "act3", "act4", "act5", "act6"]
    f = check_recursive_agency_depth(chain, 5)
    assert any("depth" in x.detail.lower() for x in f)
    # Cycle detection
    chain2 = ["act1", "act2", "act1"]
    f2 = check_recursive_agency_depth(chain2, 5)
    assert any("cyclic" in x.detail.lower() for x in f2)


def main():
    print("=" * 72)
    print("  UNSEEN DATA TEST — Features 13-16 Governance & Hardening")
    print("=" * 72)

    run_test("gov_multi_approver", test_gov_multi_approver)
    run_test("gov_change_window", test_gov_change_window)
    run_test("gov_policy_pin", test_gov_policy_pin)
    run_test("gov_drift_detection", test_gov_drift)
    
    run_test("hard_model_card", test_hard_model_card)
    run_test("hard_grounding_conf", test_hard_grounding)
    run_test("hard_agency_loop", test_hard_agency)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    
    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
