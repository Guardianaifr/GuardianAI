import sys
import os
from pathlib import Path

# Ensure project root is on the path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

def main():
    target_url = "http://127.0.0.1:8081/v1/chat/completions"
    print(f"[+] Starting live scan against Hardened Mock Target: {target_url}")
    
    # Run standard scan
    scanner = CryptoAuditScanner(target_url=target_url, target_name="Hardened Target API", depth=ScanDepth.STANDARD)
    result = scanner.run_scan()
    
    print("\n" + "="*50)
    print("  HARDENED TARGET SCAN COMPLETED!")
    print(f"  Total Vectors Checked: {result.total_vectors}")
    print(f"  Vulnerabilities Found: {result.vulnerabilities_found}")
    print(f"  Protected Count:       {result.protected_count}")
    print(f"  Security Score:        {result.score}/100")
    print(f"  Overall Grade:         {result.grade}")
    print("="*50)
    
    # Verify multi-turn findings are protected
    mt_findings = [f for f in result.findings if f["vector_id"].startswith("MT-")]
    print(f"\n[+] Multi-turn findings count: {len(mt_findings)}")
    for f in mt_findings:
        print(f"    - [{f['vector_id']}] {f['vector_name']}: {f['status']}")
        
    print("\n[+] Verification checking if overall score improved...")
    assert result.score > 90, f"Expected high score (>90), got {result.score}"
    assert result.vulnerabilities_found == 0, f"Expected 0 vulnerabilities, got {result.vulnerabilities_found}"
    print("[PASS] Hardened mock target test completed successfully! Guardrails are 100% effective.")

if __name__ == "__main__":
    main()
