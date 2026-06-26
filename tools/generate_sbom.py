from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardian.security.supply_chain import build_sbom


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SBOM from requirements with pin validation.")
    parser.add_argument("--requirements", default="requirements.txt")
    parser.add_argument("--output", default="artifacts/supply_chain/sbom.json")
    parser.add_argument("--project-name", default="guardianai-basic-launch")
    parser.add_argument("--enforce-pinned", action="store_true")
    parser.add_argument("--model-manifest", default="")
    parser.add_argument("--enforce-model-provenance", action="store_true")
    args = parser.parse_args()

    req_path = Path(args.requirements)
    if not req_path.exists():
        print(f"requirements file not found: {req_path}", file=sys.stderr)
        return 1

    model_manifest = Path(args.model_manifest) if args.model_manifest else None
    sbom = build_sbom(req_path, project_name=args.project_name, model_manifest_path=model_manifest)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    status = "ok" if sbom["validation"]["all_dependencies_pinned"] else "warning"
    print(
        json.dumps(
            {
                "status": status,
                "components": len(sbom["components"]),
                "output": str(out),
                "validation": sbom["validation"],
            }
        )
    )
    if args.enforce_pinned and not sbom["validation"]["all_dependencies_pinned"]:
        return 2
    if args.enforce_model_provenance and not sbom["validation"]["model_provenance"]["all_models_verified"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
