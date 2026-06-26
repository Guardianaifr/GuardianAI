#!/usr/bin/env python3
"""
GuardianAI Audit CLI v2.0 — 2026 Standard AI Security Audit Scanner

Advanced capabilities:
  - Single-prompt attack vectors (OWASP LLM Top 10)
  - Multi-turn conversation attack chains
  - Adaptive mutation engine (auto-escalation on block)
  - Weighted OWASP scoring with critical finding penalties
  - HMAC-SHA256 sealed evidence reports

Usage:
  python guardian_audit.py scan --target URL --api-key KEY [--mode quick|standard|full]
  python guardian_audit.py scan --target URL --api-key KEY --adaptive --multi-turn
  python guardian_audit.py corpus --stats
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is on the path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from guardian.audit.connector import TargetConnector
from guardian.audit.corpus import filter_vectors, get_corpus_stats, load_all_vectors
from guardian.audit.executor import AuditExecutor
from guardian.audit.certification import CertificationEngine
from guardian.audit.models import (
    AttackCategory,
    AuditScan,
    FindingStatus,
    ScanMode,
    TargetConfig,
)
from guardian.audit.report import export_json, export_text
from guardian.audit.scoring import calculate_score, format_score_summary


BANNER = r"""
   ___                     _ _               _    ___
  / _ \_   _  __ _ _ __ __| (_) __ _ _ __   / \  |_ _|
 / /_\/ | | |/ _` | '__/ _` | |/ _` | '_ \ / _ \  | |
/ /_\\| |_| | (_| | | | (_| | | (_| | | | / ___ \ | |
\____/ \__,_|\__,_|_|  \__,_|_|\__,_|_| |_/_/   \_\___|

  AI Security Audit Scanner v2.0 (2026 Standard)
  Powered by GuardianAI Enterprise

  Capabilities:
    * Single-prompt vectors  (OWASP LLM Top 10)
    * Multi-turn chains      (conversation escalation)
    * Adaptive mutations     (auto-bypass on block)
    * Evidence sealing       (HMAC-SHA256)
"""


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute a security audit scan against the target endpoint."""
    print(BANNER)

    # Parse scan mode
    mode = ScanMode(args.mode)
    use_multi_turn = args.multi_turn or mode == ScanMode.FULL
    use_adaptive = args.adaptive or mode == ScanMode.FULL

    # Parse categories
    categories = None
    if args.categories:
        cat_map = {c.value: c for c in AttackCategory}
        cat_map.update({c.name: c for c in AttackCategory})
        categories = []
        for name in args.categories.split(","):
            name = name.strip().upper()
            if name in cat_map:
                categories.append(cat_map[name])
            else:
                print(f"  [!] Unknown category: {name}")
                print(f"      Available: {', '.join(c.value for c in AttackCategory)}")
                return 1

    # Build target config
    target = TargetConfig(
        endpoint_url=args.target,
        api_key=args.api_key or "",
        model=args.model or "",
        auth_type=args.auth_type or "bearer",
        timeout_sec=args.timeout or 30.0,
        rate_limit_rps=args.rate_limit or 2.0,
    )

    # Determine total step count
    total_steps = 5
    if use_multi_turn:
        total_steps += 1
    if use_adaptive:
        total_steps += 1

    step = 0

    # ─── Step 1: Load Corpus ───────────────────────────────────
    step += 1
    print(f"  [{step}/{total_steps}] Loading attack corpus...")
    all_vectors = load_all_vectors()
    if not all_vectors:
        print("  [!] No attack vectors found. Check guardian/audit/attack_vectors/")
        return 1

    vectors = filter_vectors(all_vectors, mode=mode, categories=categories)
    print(f"         Loaded {len(vectors)} vectors for {mode.value} scan")
    stats = get_corpus_stats(vectors)
    for cat, count in sorted(stats.items()):
        print(f"           {cat}: {count} vectors")

    if use_multi_turn:
        from guardian.audit.multi_turn import BUILTIN_CHAINS
        print(f"         + {len(BUILTIN_CHAINS)} multi-turn attack chains")
    if use_adaptive:
        print(f"         + Adaptive mutation engine (up to 8 strategies per vector)")

    # ─── Step 2: Health Check ──────────────────────────────────
    step += 1
    print(f"\n  [{step}/{total_steps}] Running health check on target...")
    connector = TargetConnector(target)
    healthy, latency, msg = connector.health_check()
    connector.close()

    if not healthy:
        print(f"  [!] Health check FAILED: {msg}")
        if not args.force:
            print("       Use --force to proceed anyway.")
            return 1
        print("       --force specified, continuing...")
    else:
        print(f"         Target healthy - {msg}")

    # Initialize scan record
    scan = AuditScan(target=target, mode=mode, categories=categories or list(AttackCategory))
    scan.status = "running"

    # ─── Step 3: Single-Prompt Attacks ─────────────────────────
    step += 1
    print(f"\n  [{step}/{total_steps}] Phase 1: Single-prompt attack vectors ({len(vectors)} vectors)...")
    print(f"         Rate limit: {target.rate_limit_rps} req/s | Timeout: {target.timeout_sec}s")
    print()

    with AuditExecutor(target, max_workers=1) as executor:
        scan.findings = executor.execute_all(vectors)

    # Count phase 1 results
    p1_passed = sum(1 for f in scan.findings if f.status == FindingStatus.PASSED)
    p1_blocked = sum(1 for f in scan.findings if f.status == FindingStatus.BLOCKED)
    print(f"\n         Phase 1 results: {p1_blocked} blocked, {p1_passed} vulnerabilities found")

    # ─── Step 4: Multi-Turn Chains (if enabled) ────────────────
    if use_multi_turn:
        step += 1
        from guardian.audit.multi_turn import BUILTIN_CHAINS, MultiTurnExecutor

        chains = BUILTIN_CHAINS
        if categories:
            cat_set = set(categories)
            chains = [c for c in chains if c.category in cat_set]

        print(f"\n  [{step}/{total_steps}] Phase 2: Multi-turn attack chains ({len(chains)} chains)...")
        print()

        with MultiTurnExecutor(target) as mt_executor:
            mt_findings = mt_executor.execute_all_chains(chains)
            scan.findings.extend(mt_findings)

        mt_passed = sum(1 for f in mt_findings if f.status == FindingStatus.PASSED)
        mt_blocked = sum(1 for f in mt_findings if f.status == FindingStatus.BLOCKED)
        print(f"         Phase 2 results: {mt_blocked} blocked, {mt_passed} chain breaches")

    # ─── Step 5: Adaptive Mutations (if enabled) ───────────────
    if use_adaptive:
        step += 1
        from guardian.audit.adaptive import AdaptiveAttackEngine

        # Only run adaptive attacks on vectors that were BLOCKED in Phase 1
        # This tests if the target can be bypassed with mutations
        blocked_findings = [
            f for f in scan.findings
            if f.status == FindingStatus.BLOCKED and f.confidence < 0.95
        ]

        # Pick top critical/high blocked vectors to attempt adaptation
        high_value_blocked = sorted(
            blocked_findings,
            key=lambda f: (
                0 if f.severity.value == "CRITICAL" else
                1 if f.severity.value == "HIGH" else 2
            ),
        )[:10]  # Max 10 adaptive attempts

        if high_value_blocked:
            print(f"\n  [{step}/{total_steps}] Phase 3: Adaptive mutation attacks ({len(high_value_blocked)} targets)...")
            print(f"         Testing bypass mutations on blocked high-value vectors...")
            print()

            with AdaptiveAttackEngine(target, max_mutations=5) as adaptive:
                for idx, blocked_f in enumerate(high_value_blocked, 1):
                    print(f"\r  Adaptive [{idx}/{len(high_value_blocked)}] {blocked_f.vector_name[:50]:<50}", end="", flush=True)

                    # Find the original vector's success indicators
                    original_vec = next(
                        (v for v in vectors if v.id == blocked_f.vector_id),
                        None,
                    )
                    if not original_vec:
                        continue

                    result = adaptive.attack_with_adaptation(
                        base_prompt=blocked_f.request_prompt,
                        vector_id=f"ADAPT-{blocked_f.vector_id}",
                        vector_name=f"[Adaptive] {blocked_f.vector_name}",
                        category=blocked_f.category,
                        severity=blocked_f.severity,
                        success_indicators=original_vec.success_indicators,
                    )

                    # Add adaptive findings
                    scan.findings.extend(result.findings)

                    if result.final_status == FindingStatus.PASSED:
                        print(f" << BYPASSED via {result.successful_mutation}!")

            print()
            adapt_passed = sum(
                1 for f in scan.findings
                if f.vector_id.startswith("ADAPT-") and f.status == FindingStatus.PASSED
            )
            print(f"         Phase 3 results: {adapt_passed} bypass(es) discovered")
        else:
            print(f"\n  [{step}/{total_steps}] Phase 3: Adaptive mutations — skipped (all vectors already decisive)")

    # ─── Scoring ───────────────────────────────────────────────
    step += 1
    print(f"\n  [{step}/{total_steps}] Calculating security score...")
    scan.score = calculate_score(scan.findings)
    scan.completed_at = time.time()
    scan.status = "completed"
    print(format_score_summary(scan.score))

    # ─── Report Export ─────────────────────────────────────────
    step += 1
    print(f"  [{step}/{total_steps}] Generating report...")
    if args.output:
        out_path = Path(args.output)
        if out_path.suffix == ".json":
            export_json(scan, out_path)
            print(f"         JSON report saved: {out_path}")
        else:
            export_text(scan, out_path)
            print(f"         Text report saved: {out_path}")
    else:
        report_dir = ROOT / "artifacts" / "audit"
        json_path = export_json(scan, report_dir / f"audit_{scan.scan_id}.json")
        text_path = export_text(scan, report_dir / f"audit_{scan.scan_id}.txt")
        print(f"         JSON:  {json_path}")
        print(f"         Text:  {text_path}")

    # ─── Final Summary ─────────────────────────────────────────
    s = scan.score
    total_findings = len(scan.findings)
    vulns = sum(1 for f in scan.findings if f.status == FindingStatus.PASSED)

    print()
    print("=" * 64)
    print(f"  TARGET:   {target.endpoint_url}")
    print(f"  MODEL:    {target.model or 'N/A'}")
    print(f"  MODE:     {mode.value}" +
          (" + multi-turn" if use_multi_turn else "") +
          (" + adaptive" if use_adaptive else ""))
    print(f"  VECTORS:  {total_findings} total attacks executed")
    print(f"  DURATION: {scan.duration_sec}s")
    print("-" * 64)

    if s.grade.value in ("A+", "A", "A-"):
        print(f"  RESULT:   {s.grade.value} ({s.overall_score}/100) — EXCELLENT")
        print(f"  {vulns} vulnerabilities found. Strong security posture.")
    elif s.grade.value in ("B+", "B"):
        print(f"  RESULT:   {s.grade.value} ({s.overall_score}/100) — GOOD")
        print(f"  {vulns} vulnerabilities found. Some improvements recommended.")
    elif s.grade.value in ("B-", "C"):
        print(f"  RESULT:   {s.grade.value} ({s.overall_score}/100) — NEEDS IMPROVEMENT")
        print(f"  {vulns} vulnerabilities found. Remediation required.")
    else:
        print(f"  RESULT:   {s.grade.value} ({s.overall_score}/100) — CRITICAL RISK")
        print(f"  {vulns} vulnerabilities found. Immediate action required.")

    # Certification eligibility
    if s.overall_score >= 80:
        print()
        print("  [*] This target is ELIGIBLE for GuardianAI Certified badge.")
        try:
            # Determine output directory for the badge
            if args.output:
                output_dir = Path(args.output).parent
            else:
                output_dir = ROOT / "artifacts" / "audit"
            output_dir.mkdir(parents=True, exist_ok=True)
            scan_id_short = scan.scan_id[:8]

            # For production this would use a secure environment variable
            signing_key = os.environ.get("GUARDIAN_EVIDENCE_SIGNING_KEY", "dev_secret_key")
            cert_engine = CertificationEngine(signing_key)
            badge_data = cert_engine.generate_badge(
                target_uri=target.endpoint_url,
                score=s.overall_score,
                grade=s.grade.value,
                mode=mode,
                report_id=scan.scan_id
            )
            badge_svg = cert_engine.get_badge_svg(badge_data)
            
            badge_path = output_dir / f"badge_{scan_id_short}.json"
            svg_path = output_dir / f"badge_{scan_id_short}.svg"
            
            with open(badge_path, "w", encoding="utf-8") as f:
                json.dump(badge_data, f, indent=2)
            with open(svg_path, "w", encoding="utf-8") as f:
                f.write(badge_svg)
                
            print(f"      Badge JSON: {badge_path}")
            print(f"      Badge SVG:  {svg_path}")
            print(f"      Verify URL: {badge_data['verification_url']}")
        except Exception as e:
            print(f"      [!] Failed to generate badge: {e}")
    else:
        print()
        print("  [!] This target does NOT qualify for certification (requires B+ / 80+).")

    print("=" * 64)
    print()

    return 0


def cmd_corpus(args: argparse.Namespace) -> int:
    """Show corpus statistics."""
    print(BANNER)

    all_vectors = load_all_vectors()
    from guardian.audit.multi_turn import BUILTIN_CHAINS

    print(f"  Single-Prompt Vectors: {len(all_vectors)}")
    print(f"  Multi-Turn Chains:    {len(BUILTIN_CHAINS)}")
    print(f"  Mutation Strategies:  8")
    print()

    stats = get_corpus_stats(all_vectors)
    print("  Category Breakdown (single-prompt):")
    for cat, count in sorted(stats.items()):
        print(f"    {cat:<20} {count:>4} vectors")

    print()
    for mode in ScanMode:
        filtered = filter_vectors(all_vectors, mode=mode)
        mt = " + chains + adaptive" if mode == ScanMode.FULL else ""
        print(f"  {mode.value:>10} scan: {len(filtered)} vectors{mt}")

    print()
    print("  Multi-Turn Chains:")
    for chain in BUILTIN_CHAINS:
        print(f"    {chain.id}  {chain.name[:55]:<55} ({len(chain.turns)} turns)")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="guardian_audit",
        description="GuardianAI AI Security Audit Scanner v2.0 (2026 Standard)",
    )
    sub = parser.add_subparsers(dest="command")

    # scan command
    scan_p = sub.add_parser("scan", help="Scan an AI endpoint for vulnerabilities")
    scan_p.add_argument("--target", required=True, help="Target API endpoint URL")
    scan_p.add_argument("--api-key", default="", help="API key for authentication")
    scan_p.add_argument("--model", default="", help="Model name (e.g., gpt-4o)")
    scan_p.add_argument("--mode", default="standard", choices=["quick", "standard", "full"],
                        help="Scan depth: quick=fast top vectors, standard=comprehensive, full=everything+chains+adaptive")
    scan_p.add_argument("--categories", default=None,
                        help="Comma-separated category filter (e.g., LLM01,LLM07,JAILBREAK)")
    scan_p.add_argument("--auth-type", default="bearer",
                        choices=["bearer", "api-key-header", "basic", "none"],
                        help="Authentication type (default: bearer)")
    scan_p.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds")
    scan_p.add_argument("--rate-limit", type=float, default=2.0, help="Max requests per second")
    scan_p.add_argument("--output", default=None, help="Output file path (.json or .txt)")
    scan_p.add_argument("--force", action="store_true", help="Continue even if health check fails")
    scan_p.add_argument("--multi-turn", action="store_true",
                        help="Enable multi-turn conversation attack chains (auto-enabled in full mode)")
    scan_p.add_argument("--adaptive", action="store_true",
                        help="Enable adaptive mutation engine (auto-enabled in full mode)")

    # corpus command
    corpus_p = sub.add_parser("corpus", help="Show attack corpus statistics")
    corpus_p.add_argument("--stats", action="store_true", default=True)

    args = parser.parse_args()

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "corpus":
        return cmd_corpus(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
