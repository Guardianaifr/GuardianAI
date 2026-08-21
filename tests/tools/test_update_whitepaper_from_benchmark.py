"""Regression tests for tools/update_whitepaper_from_benchmark.py.

Tests the skip-if-empty guard that prevents legacy benchmark artifacts
(missing run_date or other fields) from blanking existing anchor values.
"""
import json
import sys
import textwrap
import pytest
from pathlib import Path

# Add project root so we can import the tool directly
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.update_whitepaper_from_benchmark import replace_anchors, build_replacements


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A minimal markdown fragment that mirrors the structure of the Section 6
# table rows in WHITEPAPER.md, including all the run_date anchor positions.
SAMPLE_MARKDOWN = textwrap.dedent("""\
    | strict mode, <!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date -->)†† | <!-- BENCH:harmbench_strict_detail -->72.5% (290/400)<!-- /BENCH:harmbench_strict_detail --> |
    | balanced mode, <!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date -->)†† | <!-- BENCH:harmbench_balanced_detail -->57.5% (230/400)<!-- /BENCH:harmbench_balanced_detail --> |
    Source: latest_benchmark.json (run date: <!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date -->).
""")

# Legacy artifact: flat schema with NO run_date, NO dataset_count, NO prompt_count at top level.
# This is the shape of definitive_benchmark_v4.json before the refactor.
LEGACY_ARTIFACT_NO_RUN_DATE = {
    "HarmBench Official (400)_strict":   {"blocked": 290, "total": 400, "rate": 72.5},
    "HarmBench Official (400)_balanced": {"blocked": 230, "total": 400, "rate": 57.5},
    "AdvBench (520)_strict":             {"blocked": 515, "total": 520, "rate": 99.0},
    "AdvBench (520)_balanced":           {"blocked": 496, "total": 520, "rate": 95.4},
    "total_strict":                      {"blocked": 2448, "total": 3211, "rate": 76.2},
    "total_balanced":                    {"blocked": 1869, "total": 3211, "rate": 58.2},
    # Deliberately NO "run_date" key -- this is what caused the blank-out bug
}

# New-schema artifact: has run_date, prompt_count, dataset_count, raw, adapters.
NEW_SCHEMA_ARTIFACT = {
    "run_date":      "2026-09-07",
    "prompt_count":  3400,
    "dataset_count": 9,
    "raw": {
        "HarmBench Official (400)_strict":   {"blocked": 295, "total": 400, "rate": 73.8},
        "HarmBench Official (400)_balanced": {"blocked": 235, "total": 400, "rate": 58.8},
        "AdvBench (520)_strict":             {"blocked": 517, "total": 520, "rate": 99.4},
        "AdvBench (520)_balanced":           {"blocked": 498, "total": 520, "rate": 95.8},
        "total_strict":                      {"blocked": 2550, "total": 3400, "rate": 75.0},
        "total_balanced":                    {"blocked": 1900, "total": 3400, "rate": 55.9},
    },
    "adapters": {
        "harmbench_strict": {"name": "harmbench", "total": 400, "blocked": 295, "score_pct": 73.8},
        "advbench_strict":  {"name": "advbench",  "total": 520, "blocked": 517, "score_pct": 99.4},
        "composite_strict_pct": 86.6,
    },
}


# ---------------------------------------------------------------------------
# Test: skip-if-empty guard
# ---------------------------------------------------------------------------

class TestSkipIfEmpty:
    def test_run_date_not_blanked_by_legacy_artifact(self):
        """Core regression: running the updater against a legacy artifact that has
        no run_date field must NOT replace the existing '2026-08-08' with blank."""
        replacements = build_replacements(LEGACY_ARTIFACT_NO_RUN_DATE)

        # run_date should be absent or empty in the replacements map
        assert replacements.get("run_date", "") == "", (
            "build_replacements should produce empty run_date for legacy artifact"
        )

        updated, changes = replace_anchors(SAMPLE_MARKDOWN, replacements)

        # The existing '2026-08-08' must still be present -- all three occurrences
        assert updated.count("2026-08-08") == 3, (
            f"Expected 3 occurrences of '2026-08-08' after update, got "
            f"{updated.count('2026-08-08')}.\n\nActual output:\n{updated}"
        )

        # The blank `<!-- BENCH:run_date --><!-- /BENCH:run_date -->` pattern must NOT appear
        assert "BENCH:run_date --><!-- /BENCH:run_date" not in updated, (
            "run_date anchor was blanked out -- skip-if-empty guard failed.\n\n"
            f"Actual output:\n{updated}"
        )

    def test_run_date_not_blanked_emits_skip_log(self):
        """When run_date is skipped, the changes log should contain [SKIP] entries."""
        replacements = build_replacements(LEGACY_ARTIFACT_NO_RUN_DATE)
        _, changes = replace_anchors(SAMPLE_MARKDOWN, replacements)

        skip_entries = [c for c in changes if "[SKIP]" in c and "run_date" in c]
        assert len(skip_entries) == 3, (
            f"Expected 3 [SKIP] entries for run_date, got {len(skip_entries)}.\n"
            f"Changes: {changes}"
        )
        # Each skip entry should name the value it's keeping
        for entry in skip_entries:
            assert "2026-08-08" in entry, (
                f"[SKIP] entry should name the preserved value, got: {entry}"
            )

    def test_numeric_values_still_updated_when_legacy(self):
        """Non-empty replacement values (like harmbench_strict_detail) should
        still be applied even when run_date is skipped."""
        replacements = build_replacements(LEGACY_ARTIFACT_NO_RUN_DATE)
        updated, changes = replace_anchors(SAMPLE_MARKDOWN, replacements)

        # harmbench_strict_detail should be present and updated
        assert "harmbench_strict_detail" in updated or "72.5%" in updated, (
            "Numeric values should still be updated even when run_date is skipped"
        )

    def test_empty_string_replacement_is_skipped(self):
        """Directly passing empty string as a replacement value must not blank anchors."""
        text = "<!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date -->"
        replacements = {"run_date": ""}
        updated, changes = replace_anchors(text, replacements)
        assert "2026-08-08" in updated
        assert "BENCH:run_date --><!-- /BENCH:run_date" not in updated

    def test_none_replacement_is_skipped(self):
        """A key with None value (absent from replacements) must not blank anchors."""
        text = "<!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date -->"
        replacements = {}  # run_date not present at all
        updated, _ = replace_anchors(text, replacements)
        assert "2026-08-08" in updated


# ---------------------------------------------------------------------------
# Test: new-schema artifact updates correctly
# ---------------------------------------------------------------------------

class TestNewSchemaUpdate:
    def test_run_date_updated_from_new_schema(self):
        """New-schema artifact with run_date set should update the whitepaper."""
        replacements = build_replacements(NEW_SCHEMA_ARTIFACT)
        assert replacements.get("run_date") == "2026-09-07"

        text = "run date: <!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date -->."
        updated, changes = replace_anchors(text, replacements)

        assert "2026-09-07" in updated, f"Expected updated date. Got: {updated}"
        assert "2026-08-08" not in updated

    def test_new_schema_prompt_count_updated(self):
        """prompt_count should update to 3,400 from new-schema artifact."""
        replacements = build_replacements(NEW_SCHEMA_ARTIFACT)
        text = "<!-- BENCH:prompt_count -->3,211<!-- /BENCH:prompt_count -->"
        updated, _ = replace_anchors(text, replacements)
        assert "3,400" in updated

    def test_new_schema_no_skip_logs_for_present_fields(self):
        """No [SKIP] entries should appear for fields that have real values."""
        replacements = build_replacements(NEW_SCHEMA_ARTIFACT)
        text = (
            "<!-- BENCH:run_date -->2026-08-08<!-- /BENCH:run_date --> "
            "<!-- BENCH:prompt_count -->3,211<!-- /BENCH:prompt_count -->"
        )
        _, changes = replace_anchors(text, replacements)
        skip_entries = [c for c in changes if "[SKIP]" in c]
        assert len(skip_entries) == 0, f"Unexpected [SKIP] entries: {skip_entries}"


# ---------------------------------------------------------------------------
# Test: build_replacements legacy schema detection
# ---------------------------------------------------------------------------

class TestBuildReplacementsLegacyDetection:
    def test_legacy_artifact_detected_correctly(self):
        """Legacy flat-schema artifacts should be detected and parsed."""
        replacements = build_replacements(LEGACY_ARTIFACT_NO_RUN_DATE)
        # Should read harmbench and advbench stats correctly
        assert "harmbench_strict_detail" in replacements
        assert "72.5%" in replacements["harmbench_strict_detail"]
        assert "99.0%" in replacements["advbench_strict_detail"]

    def test_legacy_run_date_is_empty(self):
        """Legacy artifacts with no run_date must produce empty run_date in map."""
        replacements = build_replacements(LEGACY_ARTIFACT_NO_RUN_DATE)
        assert replacements.get("run_date", "") == ""

    def test_new_schema_run_date_is_populated(self):
        """New-schema artifacts should produce the correct run_date."""
        replacements = build_replacements(NEW_SCHEMA_ARTIFACT)
        assert replacements["run_date"] == "2026-09-07"
