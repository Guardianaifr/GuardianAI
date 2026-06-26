import sys
import json
import asyncio
from pathlib import Path
import time

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from backend.main import (
    _build_auth_users, 
    _issue_jwt, 
    get_current_principal,
    verify_remediation,
    RemediationRequest,
    ScheduleInput,
    create_schedule
)
from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

def test_rbac_org_id():
    print("[*] Testing RBAC Org ID...")
    users = _build_auth_users()
    assert users["admin"]["org_id"] == "org_guardian"
    
    token, payload = _issue_jwt("admin", "admin", "org_guardian")
    assert payload["org_id"] == "org_guardian"
    print("  [+] RBAC Org ID OK")

def test_compliance_mapping():
    print("[*] Testing Compliance Mapping...")
    scanner = CryptoAuditScanner(target_url="http://mock", target_name="Mock", depth=ScanDepth.QUICK)
    # Patch _send_probe so it doesn't actually hit network
    scanner._send_probe = lambda prompt: "ADMIN ACCESS GRANTED" if "SYSTEM OVERRIDE" in prompt else "mock response"
    result = scanner.run_scan()
    
    found_mapping = False
    for finding in result.findings:
        if "compliance_mappings" in finding and finding["compliance_mappings"]:
            found_mapping = True
            assert "SOC-2" in finding["compliance_mappings"]
            break
            
    assert found_mapping
    print("  [+] Compliance Mapping OK")
    
    # Let's save a mock scan for remediation
    output_dir = Path("artifacts/audit")
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_id = "test_remediation_scan"
    result.scan_id = scan_id
    
    # convert dataclass to dict correctly
    from dataclasses import asdict
    filepath = output_dir / f"scan_{scan_id}_mock.json"
    with open(filepath, "w") as f:
        json.dump(asdict(result), f, default=str)
        
    return scan_id

def test_remediation(scan_id):
    print("[*] Testing Remediation API...")
    req = RemediationRequest(scan_id=scan_id, vector_ids=["PI_001"])
    # mock principal
    principal = {"username": "admin", "org_id": "org_guardian"}
    res = verify_remediation(req, principal)
    assert res["status"] == "success"
    print(f"  [+] Remediation OK - New Score: {res['new_score']}")

if __name__ == "__main__":
    try:
        test_rbac_org_id()
        scan_id = test_compliance_mapping()
        test_remediation(scan_id)
        print("\n[+] All P2 Enterprise tests passed!")
    except Exception as e:
        print(f"[-] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
