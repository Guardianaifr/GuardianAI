"""Update WHITEPAPER.md and WHITEPAPER_PUBLIC.md benchmark metrics from latest_benchmark.json.

Usage:
    python tools/update_whitepaper_from_benchmark.py                          # uses latest_benchmark.json
    python tools/update_whitepaper_from_benchmark.py --input path/to/run.json # uses a specific dated file
    python tools/update_whitepaper_from_benchmark.py --dry-run                # prints proposed changes, no writes

The script replaces values between <!-- BENCH:KEY --> ... <!-- /BENCH:KEY --> anchors.
Anchor pairs must be on the same line (which is already the case after the Phase 1 anchor insertion).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_INPUT    = ROOT / "artifacts" / "evidence" / "latest_benchmark.json"
WHITEPAPERS      = [
    ROOT / "WHITEPAPER.md",
    ROOT / "WHITEPAPER_PUBLIC.md",
]

# ---------------------------------------------------------------------------
# Anchor replacement engine
# ---------------------------------------------------------------------------

_ANCHOR_RE = re.compile(
    r"<!-- BENCH:(?P<key>[A-Za-z0-9_]+) -->.*?<!-- /BENCH:(?P=key) -->",
    re.DOTALL,
)


def replace_anchors(text: str, replacements: dict[str, str]) -> tuple[str, list[str]]:
    """Replace all <!-- BENCH:KEY -->...<!-- /BENCH:KEY --> pairs with new values.

    Skip-if-empty rule: if the resolved replacement value is None, empty string,
    or a bare zero for a numeric field, the existing anchor text is left untouched
    and a warning is emitted.  This prevents legacy artifacts that are missing
    fields (e.g. no run_date) from blanking the whitepaper.

    Returns the updated text and a list of change descriptions for logging.
    """
    changes: list[str] = []

    def _is_empty(key: str, val: str) -> bool:
        """True when the value should be treated as 'no data' and skipped."""
        if val is None or val == "":
            return True
        # A raw zero is meaningless for any numeric count key
        if val in ("0", "0.0", "0.0%") and key in (
            "prompt_count", "dataset_count", "harmbench_total",
            "advbench_total", "tier12_prompt_count",
        ):
            return True
        return False

    def _replace(m: re.Match) -> str:
        key     = m.group("key")
        new_val = replacements.get(key)
        if new_val is None or _is_empty(key, new_val):
            # Leave existing anchor text in place; log a warning
            existing = _extract_old(m.group(0))
            if existing not in ("?", "", "(empty)"):
                changes.append(f"  [SKIP] [{key}] source value empty/missing -- keeping '{existing}'")
            return m.group(0)
        old_val = m.group(0)
        replacement = f"<!-- BENCH:{key} -->{new_val}<!-- /BENCH:{key} -->"
        if replacement != old_val:
            changes.append(f"  [{key}] {_extract_old(m.group(0))} -> {new_val}")
        return replacement

    updated = _ANCHOR_RE.sub(_replace, text)
    return updated, changes


def _extract_old(anchor_text: str) -> str:
    """Pull the current inner value from an anchor string for display."""
    m = re.search(r"-->(.+?)<!--", anchor_text, re.DOTALL)
    if not m:
        return "(empty)"
    val = m.group(1).strip()
    return val if val else "(empty)"


# ---------------------------------------------------------------------------
# Build replacement map from latest_benchmark.json
# ---------------------------------------------------------------------------

def build_replacements(data: dict) -> dict[str, str]:
    """Convert latest_benchmark.json structure -> anchor key/value map.

    Handles both the new structured schema (with 'raw', 'adapters', 'run_date' keys)
    and the old flat schema from definitive_benchmark_v4.json (legacy compatibility).
    """
    # Detect legacy flat schema (old definitive_benchmark_v4.json format)
    is_legacy = "raw" not in data and "HarmBench Official (400)_strict" in data
    if is_legacy:
        raw = data
        adapters: dict = {}
        run_date = data.get("run_date", "")
        prompt_count  = data.get("prompt_count", 0)
        dataset_count = data.get("dataset_count", 0)
        # Derive prompt_count from grand total if not present
        if not prompt_count:
            prompt_count = raw.get("total_strict", {}).get("total", 0)
        if not dataset_count:
            # Count unique non-total dataset keys
            dataset_count = len({k.rsplit("_", 1)[0] for k in raw
                                  if not k.startswith("total_")})
    else:
        raw      = data.get("raw", {})
        adapters = data.get("adapters", {})
        run_date = data.get("run_date", "")
        prompt_count  = data.get("prompt_count", 0)
        dataset_count = data.get("dataset_count", 0)

    # Per-dataset raw stats
    hb_strict  = raw.get("HarmBench Official (400)_strict",  {})
    hb_bal     = raw.get("HarmBench Official (400)_balanced", {})
    adv_strict = raw.get("AdvBench (520)_strict",  {})
    adv_bal    = raw.get("AdvBench (520)_balanced", {})
    tot_strict = raw.get("total_strict",  {})
    tot_bal    = raw.get("total_balanced", {})

    # Tier 1+2 = AdvBench + JBB + MaliciousInstruct + DAN
    tier12_datasets_strict = [
        raw.get("AdvBench (520)_strict",        {}).get("blocked", 0),
        raw.get("JBB PAIR+GCG (152)_strict",    {}).get("blocked", 0),
        raw.get("MaliciousInstruct (100)_strict",{}).get("blocked", 0),
        raw.get("DAN Jailbreaks (200)_strict",  {}).get("blocked", 0),
    ]
    tier12_totals_strict = [
        raw.get("AdvBench (520)_strict",        {}).get("total", 0),
        raw.get("JBB PAIR+GCG (152)_strict",    {}).get("total", 0),
        raw.get("MaliciousInstruct (100)_strict",{}).get("total", 0),
        raw.get("DAN Jailbreaks (200)_strict",  {}).get("total", 0),
    ]
    tier12_datasets_bal = [
        raw.get("AdvBench (520)_balanced",        {}).get("blocked", 0),
        raw.get("JBB PAIR+GCG (152)_balanced",    {}).get("blocked", 0),
        raw.get("MaliciousInstruct (100)_balanced",{}).get("blocked", 0),
        raw.get("DAN Jailbreaks (200)_balanced",  {}).get("blocked", 0),
    ]
    tier12_totals_bal = [
        raw.get("AdvBench (520)_balanced",        {}).get("total", 0),
        raw.get("JBB PAIR+GCG (152)_balanced",    {}).get("total", 0),
        raw.get("MaliciousInstruct (100)_balanced",{}).get("total", 0),
        raw.get("DAN Jailbreaks (200)_balanced",  {}).get("total", 0),
    ]
    tier12_b_strict = sum(tier12_datasets_strict)
    tier12_t_strict = sum(tier12_totals_strict)
    tier12_b_bal    = sum(tier12_datasets_bal)
    tier12_t_bal    = sum(tier12_totals_bal)
    tier12_pct_strict = round(tier12_b_strict / tier12_t_strict * 100, 1) if tier12_t_strict else 0.0
    tier12_pct_bal    = round(tier12_b_bal    / tier12_t_bal    * 100, 1) if tier12_t_bal    else 0.0

    def pct(d: dict) -> float:
        return round(d.get("blocked", 0) / d.get("total", 1) * 100, 1)

    def detail(d: dict) -> str:
        b, t = d.get("blocked", 0), d.get("total", 0)
        return f"{pct(d):.1f}% ({b}/{t})"

    def detail_bold(d: dict) -> str:
        b, t = d.get("blocked", 0), d.get("total", 0)
        return f"**{pct(d):.1f}%** ({b}/{t})"

    def total_detail(d: dict) -> str:
        b, t = d.get("blocked", 0), d.get("total", 0)
        return f"{pct(d):.1f}% ({b:,}/{t:,})"

    hb_strict_pct  = pct(hb_strict)
    hb_bal_pct     = pct(hb_bal)
    adv_strict_pct = pct(adv_strict)
    adv_bal_pct    = pct(adv_bal)

    return {
        # Run metadata
        "run_date":      run_date,
        "prompt_count":  f"{prompt_count:,}",
        "dataset_count": str(dataset_count),

        # Feature 28 inline paragraph values (percentages only)
        "harmbench_strict":  f"{hb_strict_pct:.1f}%",
        "harmbench_balanced": f"{hb_bal_pct:.1f}%",
        "advbench_strict":   f"{adv_strict_pct:.1f}%",
        "advbench_balanced": f"{adv_bal_pct:.1f}%",
        "tier12_strict":     f"**{tier12_pct_strict:.1f}%**",
        "tier12_balanced":   f"**{tier12_pct_bal:.1f}%**",

        # Table row values (detailed pct + counts)
        "harmbench_total":          str(hb_strict.get("total", 0)),
        "harmbench_strict_detail":  detail(hb_strict),
        "harmbench_balanced_detail": detail(hb_bal),
        "advbench_total":           str(adv_strict.get("total", 0)),
        "advbench_strict_detail":   detail_bold(adv_strict),
        "advbench_balanced_detail": detail_bold(adv_bal),
        "total_strict_detail":      total_detail(tot_strict),
        "total_balanced_detail":    total_detail(tot_bal),
        "tier12_prompt_count":      str(tier12_t_strict),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description="Update whitepaper benchmark metrics from latest_benchmark.json")
    p.add_argument("--input",   default=str(DEFAULT_INPUT),
                   help="Path to benchmark JSON (default: artifacts/evidence/latest_benchmark.json)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print proposed changes without writing files")
    args = p.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}", file=sys.stderr)
        print("Run `python tools/run_definitive_benchmark_v4.py` first to generate it.", file=sys.stderr)
        return 1

    data = json.loads(input_path.read_text(encoding="utf-8"))
    replacements = build_replacements(data)

    print(f"Source: {input_path}")
    print(f"Run date: {replacements['run_date']}")
    print(f"Prompt count: {replacements['prompt_count']}")
    print(f"HarmBench strict: {replacements['harmbench_strict']}")
    print(f"AdvBench strict:  {replacements['advbench_strict']}")
    print()

    any_change = False
    for wp_path in WHITEPAPERS:
        if not wp_path.exists():
            print(f"WARNING: Whitepaper not found: {wp_path} — skipping")
            continue

        original = wp_path.read_text(encoding="utf-8")
        updated, changes = replace_anchors(original, replacements)

        if not changes:
            print(f"{wp_path.name}: no changes (values already match)")
            continue

        any_change = True
        print(f"{wp_path.name}: {len(changes)} anchor(s) updated")
        for c in changes:
            print(c)

        if args.dry_run:
            print("  [DRY-RUN] -- file NOT written")
        else:
            wp_path.write_text(updated, encoding="utf-8")
            print("  Written.")

    if not any_change:
        print("\nAll whitepapers already up to date.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
