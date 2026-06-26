from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardian.security.supply_chain import create_release_manifest, sign_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Create signed release artifact manifest.")
    parser.add_argument("--artifact", action="append", required=True, help="Artifact path (repeatable).")
    parser.add_argument("--manifest-out", default="artifacts/supply_chain/release_manifest.json")
    parser.add_argument("--signature-out", default="artifacts/supply_chain/release_manifest.sig")
    parser.add_argument("--key-env", default="GUARDIAN_RELEASE_SIGNING_KEY")
    args = parser.parse_args()

    key = os.environ.get(args.key_env, "").strip()
    if not key:
        print(f"missing signing key in env var: {args.key_env}", file=sys.stderr)
        return 1

    artifact_paths = [Path(p) for p in args.artifact]
    missing = [str(p) for p in artifact_paths if not p.exists()]
    if missing:
        print(json.dumps({"error": "artifact missing", "paths": missing}))
        return 2

    manifest = create_release_manifest(artifact_paths)
    signature = sign_manifest(manifest, key)

    manifest_out = Path(args.manifest_out)
    signature_out = Path(args.signature_out)
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    signature_out.parent.mkdir(parents=True, exist_ok=True)
    manifest_out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    signature_out.write_text(signature + "\n", encoding="utf-8")

    print(json.dumps({"status": "ok", "manifest": str(manifest_out), "signature": str(signature_out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
