from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardian.security.supply_chain import verify_model_provenance


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify model artifact provenance from manifest.")
    parser.add_argument("--model-manifest", required=True)
    args = parser.parse_args()

    manifest = Path(args.model_manifest)
    report = verify_model_provenance(manifest)
    print(json.dumps(report))
    return 0 if report.get("all_models_verified", False) else 2


if __name__ == "__main__":
    raise SystemExit(main())
