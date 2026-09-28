"""
GuardianAI Attestation Latency Benchmark
=========================================
Measures the end-to-end latency of SafetyAttestationService.evaluate_and_attest()
over N iterations, covering:
  - Calldata hashing (keccak256)
  - Risk scoring (InputFilter + TransactionAnalyzer)
  - EIP-712 struct construction
  - ECDSA signing (secp256k1)
  - ABI encoding for GuardianPolicyGuard wrapping

Usage:
    python tools/benchmark_attestation_latency.py [--iterations 100]
"""
import argparse
import os
import statistics
import sys
import time

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from guardian.relayer.attestation_service import SafetyAttestationService


def run_benchmark(iterations: int = 100) -> None:
    """Run the attestation benchmark and print statistics."""
    print("=" * 70)
    print("GuardianAI Attestation Latency Benchmark")
    print("=" * 70)

    # Initialize service with ephemeral key (no env dependency)
    service = SafetyAttestationService(
        private_key="0x" + "ab" * 32,  # Deterministic test key
        verifying_contract=os.getenv("GUARDIAN_POLICY_GUARD_CONTRACT_MONAD", "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60"),
        chain_id=10143,
        max_allowed_risk_score=25,
        ttl_seconds=300,
    )

    # Standard ERC-20 transfer calldata: transfer(address,uint256)
    # selector(4) + address(32) + uint256(32) = 68 bytes = 136 hex chars
    test_calldata = (
        "0xa9059cbb"  # transfer selector
        + "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"  # address padded to 32 bytes
        + "0000000000000000000000000000000000000000000000000de0b6b3a7640000"  # 1e18 padded to 32 bytes
    )
    test_target = "0x1234567890abcdef1234567890abcdef12345678"
    test_agent_id = "benchmark-agent-001"
    test_prompt = "Transfer 1 token to recipient"

    # Warm-up run (JIT, import caching, etc.)
    print(f"\n[+] Warming up ({3} iterations)...")
    for _ in range(3):
        service.evaluate_and_attest(
            agent_id=test_agent_id,
            target=test_target,
            data=test_calldata,
            value=0,
            prompt=test_prompt,
        )

    # Benchmark
    print(f"[+] Running {iterations} iterations...")
    latencies_ms = []

    for i in range(iterations):
        # Use unique nonces to avoid any caching effects
        start = time.perf_counter()
        result = service.evaluate_and_attest(
            agent_id=test_agent_id,
            target=test_target,
            data=test_calldata,
            value=0,
            prompt=test_prompt,
            nonce=i + 1000,
        )
        end = time.perf_counter()

        elapsed_ms = (end - start) * 1000
        latencies_ms.append(elapsed_ms)

    # Statistics
    latencies_ms.sort()
    p50 = latencies_ms[len(latencies_ms) // 2]
    p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]
    mean = statistics.mean(latencies_ms)
    stdev = statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0
    minimum = min(latencies_ms)
    maximum = max(latencies_ms)

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"  Iterations : {iterations}")
    print(f"  Last Status: {result.status} (risk_score={result.risk_score})")
    print(f"  --------------------------------------")
    print(f"  P50 (Median) : {p50:.3f} ms")
    print(f"  P95          : {p95:.3f} ms")
    print(f"  P99          : {p99:.3f} ms")
    print(f"  Mean         : {mean:.3f} ms")
    print(f"  Std Dev      : {stdev:.3f} ms")
    print(f"  Min          : {minimum:.3f} ms")
    print(f"  Max          : {maximum:.3f} ms")
    print("=" * 70)

    # Machine info
    import platform
    print(f"\n  Platform: {platform.platform()}")
    print(f"  Python  : {platform.python_version()}")
    print(f"  CPU     : {platform.processor()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark GuardianAI attestation latency")
    parser.add_argument("--iterations", type=int, default=100, help="Number of benchmark iterations")
    args = parser.parse_args()
    run_benchmark(args.iterations)
