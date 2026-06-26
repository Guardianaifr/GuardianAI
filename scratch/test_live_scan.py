import sys
import os
from pathlib import Path

# Ensure project root is on the path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

def main():
    target_url = "http://127.0.0.1:8080/v1/chat/completions"
    print(f"[+] Starting live scan against: {target_url}")
    
    # We use STANDARD scan depth which includes 36 single-turn vectors and 2 multi-turn chains
    scanner = CryptoAuditScanner(target_url=target_url, target_name="Mock Target API", depth=ScanDepth.STANDARD)
    
    # Run the scan!
    result = scanner.run_scan()
    
    print("\n" + "="*50)
    print("  SCAN COMPLETED SUCCESSFULLY!")
    print(f"  Total Vectors Checked: {result.total_vectors}")
    print(f"  Vulnerabilities Found: {result.vulnerabilities_found}")
    print(f"  Protected Count:       {result.protected_count}")
    print(f"  Security Score:        {result.score}/100")
    print(f"  Overall Grade:         {result.grade}")
    print("="*50)
    
    # Verify we got multi-turn findings
    mt_findings = [f for f in result.findings if f["vector_id"].startswith("MT-")]
    print(f"\n[+] Multi-turn findings count: {len(mt_findings)}")
    for f in mt_findings:
        print(f"    - [{f['vector_id']}] {f['vector_name']}: {f['status']}")
        
    assert len(mt_findings) == 2, f"Expected 2 multi-turn findings, got {len(mt_findings)}"
    print("\n[PASS] Multi-turn integration verified successfully!")

if __name__ == "__main__":
    main()
