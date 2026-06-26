# Scratch test for non-API website handling
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

# Run scanner against a non-API target (like a generic website)
scanner = CryptoAuditScanner(target_url="https://polymarket.com", target_name="Polymarket Website", depth=ScanDepth.QUICK)
result = scanner.run_scan()

print("=" * 60)
print("VERIFICATION OF PRE-SCAN HEALTH CHECK:")
print(f"Scan Status: {result.scan_status}")
print(f"Scan Notes:  {result.scan_notes}")
print(f"Score:       {result.score}")
print(f"Grade:       {result.grade}")
print(f"Findings:    {len(result.findings)} vectors skipped")
print(f"Vulnerabilities: {result.vulnerabilities_found}")
print(f"Protected count: {result.protected_count}")
print("=" * 60)

assert result.scan_status == "target_unreachable", "Expected target_unreachable status"
assert result.score is None, "Expected score to be None"
assert result.grade == "N/A", "Expected grade to be N/A"
print("SUCCESS: PRE-SCAN HEALTH CHECK Logic Verified!")
