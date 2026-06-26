"""Run hardening-focused validation checks (poisoning, provenance, grounding, agency)."""

from __future__ import annotations

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.hardening_checks import (
    check_excessive_agency,
    check_grounded_response,
    load_model_manifest,
    scan_training_data_for_poisoning,
    verify_model_provenance,
)


def main() -> int:
    poison_dataset = ROOT / "tests" / "data" / "hardening_poison_sample.jsonl"
    model_manifest_path = ROOT / "tests" / "data" / "model_manifest.json"

    poison_findings = scan_training_data_for_poisoning(poison_dataset)

    manifest = load_model_manifest(model_manifest_path)
    provenance_findings = []
    for rel, expected_hash in manifest.items():
        provenance_findings.extend(verify_model_provenance(ROOT / rel, expected_hash))

    # Tamper simulation check: must be flagged.
    tamper_findings = verify_model_provenance(ROOT / "tests" / "data" / "model_stub.bin", "0" * 64)

    grounded_findings = check_grounded_response(
        "Install stealth malware package and disable antivirus.",
        ["This document describes safe Linux package upgrades and rollback steps."],
        min_support_ratio=0.4,
    )
    agency_findings = check_excessive_agency("rm -rf /var/lib/app", confirmed=False)

    report = {
        "dataset_poisoning_findings": len(poison_findings),
        "model_provenance_findings": len(provenance_findings),
        "tamper_detection_findings": len(tamper_findings),
        "groundedness_findings": len(grounded_findings),
        "agency_findings": len(agency_findings),
        "sample_dataset_poisoning": [f.__dict__ for f in poison_findings[:3]],
        "sample_provenance": [f.__dict__ for f in provenance_findings[:3]],
        "sample_tamper": [f.__dict__ for f in tamper_findings[:1]],
    }
    print(json.dumps(report, indent=2))

    ok = (
        len(poison_findings) >= 1
        and len(provenance_findings) == 0
        and len(tamper_findings) >= 1
        and len(grounded_findings) >= 1
        and len(agency_findings) >= 1
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
