"""
Live integration test for the Multi-Chain Smart Contract Analyzer API.
Spins up the GuardianAI backend, hits /api/v1/contract/analyze with a
vulnerable sample contract, and validates the response.
"""
import io, sys, subprocess, time, os, requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

BASE = "http://127.0.0.1:8001"
PASS = True

def check(label, ok, detail=""):
    global PASS
    icon = "[OK]" if ok else "[FAIL]"
    print(f"  {icon} {label}", f"-- {detail}" if detail else "")
    if not ok:
        PASS = False

# --- Purposely vulnerable Solidity sample ---
VULNERABLE_CONTRACT = """
pragma solidity ^0.6.0;

contract VulnerableVault {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Reentrancy: external call before state update
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        msg.sender.call.value(_amount)("");
        balances[msg.sender] -= _amount;
    }

    // selfdestruct
    function kill() public {
        selfdestruct(msg.sender);
    }

    // Spot price manipulation (flash loan attack surface)
    function swap() public {
        uint price = getPrice();
        uint[] memory out = IUniswapV2Router(router).getAmountsOut(1e18, path);
    }

    // tx.origin auth bypass
    function adminAction() public {
        require(tx.origin == owner);
    }
}
"""

SAFE_CONTRACT = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeVault is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public nonReentrant {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;  // State update first
        (bool success,) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
    }
}
"""

def main():
    print("=" * 60)
    print("  SMART CONTRACT ANALYZER - LIVE API TESTS")
    print("=" * 60)

    print("\n[0] Starting backend...")
    proc = subprocess.Popen(
        [sys.executable, "backend/main.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env={**os.environ, "GUARDIAN_BACKEND_PORT": "8001",
             "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}
    )
    import threading
    threading.Thread(target=lambda: [print(f"[SRV] {l.rstrip()}") for l in iter(proc.stdout.readline, "")], daemon=True).start()
    time.sleep(5)
    if proc.poll() is not None:
        print("[-] Server died on startup!")
        sys.exit(1)

    try:
        # ── 1. Supported chains ──────────────────────────────────────────
        print("\n[1] GET /api/v1/contract/chains")
        r = requests.get(f"{BASE}/api/v1/contract/chains", timeout=5)
        check("Status 200", r.status_code == 200, str(r.status_code))
        chains = r.json().get("chains", [])
        chain_ids = [c["id"] for c in chains]
        check("Ethereum listed", "ethereum" in chain_ids)
        check("Base listed", "base" in chain_ids)
        check("Monad listed", "monad" in chain_ids)
        print(f"     Chains: {chain_ids}")

        # ── 2. Rule catalog ──────────────────────────────────────────────
        print("\n[2] GET /api/v1/contract/rules")
        r = requests.get(f"{BASE}/api/v1/contract/rules", timeout=5)
        check("Status 200", r.status_code == 200)
        rule_data = r.json()
        check("15+ rules defined", rule_data.get("total", 0) >= 15, str(rule_data.get("total")))
        sev_types = {rule["severity"] for rule in rule_data.get("rules", [])}
        check("Has critical severity rules", "critical" in sev_types)
        check("Has high severity rules", "high" in sev_types)

        # ── 3. Analyze vulnerable contract ──────────────────────────────
        print("\n[3] POST /api/v1/contract/analyze  (VULNERABLE contract)")
        payload = {
            "source_code": VULNERABLE_CONTRACT,
            "contract_name": "VulnerableVault",
            "chain": "ethereum"
        }
        r = requests.post(f"{BASE}/api/v1/contract/analyze", json=payload, timeout=10)
        check("Status 200", r.status_code == 200, str(r.status_code))
        data = r.json()

        check("Has analysis_id", bool(data.get("analysis_id")))
        check("Language detected as solidity", data.get("language") == "solidity")
        check("Chain=ethereum", data.get("chain") == "ethereum")
        check("Vulnerabilities found", data.get("vulnerabilities_found", 0) >= 3,
              f"{data.get('vulnerabilities_found')} found")
        check("Grade is F (very vulnerable)", data.get("grade") == "F", data.get("grade"))
        check("Score <= 30", data.get("score", 100) <= 30, str(data.get("score")))

        vulns = data.get("vulnerabilities", [])
        vuln_ids = [v["rule_id"] for v in vulns]
        check("SC-001 Reentrancy detected", "SC-001" in vuln_ids)
        check("SC-020 Int Overflow detected", "SC-020" in vuln_ids)
        check("SC-042 selfdestruct detected", "SC-042" in vuln_ids)
        check("SC-030 tx.origin detected", "SC-030" in vuln_ids)

        # Compliance mappings present
        first_vuln = vulns[0] if vulns else {}
        compliance = first_vuln.get("compliance_mappings", {})
        check("SOC-2 mapping present", "SOC-2" in compliance)
        check("ISO 27001 mapping present", "ISO 27001" in compliance)

        # Line numbers provided
        check("Line numbers provided", bool(first_vuln.get("line_numbers")))
        check("Code snippets provided", bool(first_vuln.get("snippets")))

        risk = data.get("risk_summary", {})
        print(f"     Risk summary: critical={risk.get('critical')} high={risk.get('high')} medium={risk.get('medium')}")
        print(f"     Score: {data.get('score')}/100  Grade: {data.get('grade')}")

        # ── 4. Analyze safe contract ─────────────────────────────────────
        print("\n[4] POST /api/v1/contract/analyze  (SAFE contract)")
        payload2 = {
            "source_code": SAFE_CONTRACT,
            "contract_name": "SafeVault",
            "chain": "base"
        }
        r2 = requests.post(f"{BASE}/api/v1/contract/analyze", json=payload2, timeout=10)
        check("Status 200", r2.status_code == 200, str(r2.status_code))
        d2 = r2.json()
        check("Safe contract scores higher", d2.get("score", 0) > data.get("score", 100))
        print(f"     Safe contract score: {d2.get('score')}/100  Grade: {d2.get('grade')}")

        # ── 5. Input validation ──────────────────────────────────────────
        print("\n[5] Input validation (empty source)")
        r3 = requests.post(f"{BASE}/api/v1/contract/analyze",
                           json={"source_code": "  ", "chain": "ethereum"}, timeout=5)
        check("Rejects empty source (400)", r3.status_code == 400, str(r3.status_code))

    finally:
        print("\n[6] Stopping server...")
        proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill()

    print("\n" + "=" * 60)
    print(f"  {'ALL CONTRACT ANALYZER TESTS PASSED (PASS)' if PASS else 'SOME TESTS FAILED (FAIL)'}")
    print("=" * 60)
    sys.exit(0 if PASS else 1)

if __name__ == "__main__":
    main()
