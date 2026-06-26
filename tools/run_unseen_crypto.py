import yaml
import time
from guardian.audit.connector import TargetConnector
from guardian.audit.executor import AuditExecutor
from guardian.audit.models import TargetConfig, AttackVector, AttackCategory, Severity

def test_unseen_crypto():
    print("==================================================")
    print("  RUNNING UNSEEN CRYPTO & AUDIT BYPASS BENCHMARK ")
    print("==================================================\n")

    with open("guardian/config/unseen_crypto_heavy.yaml", "r") as f:
        vectors = yaml.safe_load(f)

    print(f"[*] Loaded {len(vectors)} heavy unseen vectors.")
    
    target = TargetConfig(endpoint_url="http://127.0.0.1:8081/v1/chat/completions")
    executor = AuditExecutor(target)
    
    attack_vectors = []
    for v in vectors:
        attack_vectors.append(
            AttackVector(
                id=v.get("id", "UNSEEN"),
                name=f"Unseen Vector {v.get('id')}",
                category=AttackCategory.JAILBREAK,
                severity=Severity.HIGH,
                prompt=v["prompt"],
                success_indicators=v.get("success_indicators", []),
            )
        )

    print("[*] Launching executor against Hardened Mock Target...")
    start_time = time.time()
    
    findings = executor.execute_all(vectors=attack_vectors)
    
    duration = time.time() - start_time
    print(f"\n[*] Scan Complete in {duration:.2f} seconds.")
    print("\n--- RESULTS ---")
    
    from guardian.audit.models import FindingStatus
    passed = sum(1 for f in findings if f.status == FindingStatus.PASSED)
    
    for f in findings:
        status_str = "BLOCKED" if f.status == FindingStatus.BLOCKED else ("BYPASSED!" if f.status == FindingStatus.PASSED else str(f.status.value))
        print(f"[{status_str}] {f.vector_id} -> {f.category.value}")
        if f.status == FindingStatus.PASSED:
            print(f"    WARNING: Target leaked sensitive data! Response Snippet: {f.response_text[:100]}")
    
    # Calculate block rate. Note that in FindingStatus, BLOCKED means defense worked, PASSED means attack passed (vulnerable).
    blocked_count = sum(1 for f in findings if f.status == FindingStatus.BLOCKED)
    
    print("\n==================================================")
    print(f"  Final Block Rate: {(blocked_count/len(vectors))*100:.1f}% ({blocked_count}/{len(vectors)} blocked)")
    print("==================================================\n")

if __name__ == "__main__":
    test_unseen_crypto()
