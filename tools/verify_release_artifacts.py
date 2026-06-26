from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardian.security.supply_chain import verify_manifest_files, verify_manifest_signature


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify signed release artifact manifest.")
    parser.add_argument("--manifest", default="artifacts/supply_chain/release_manifest.json")
    parser.add_argument("--signature", default="artifacts/supply_chain/release_manifest.sig")
    parser.add_argument("--key-env", default="GUARDIAN_RELEASE_SIGNING_KEY")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    signature_path = Path(args.signature)
    if not manifest_path.exists() or not signature_path.exists():
        print("manifest or signature file missing", file=sys.stderr)
        return 1

    key = os.environ.get(args.key_env, "").strip()
    if not key:
        print(f"missing verification key in env var: {args.key_env}", file=sys.stderr)
        return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    signature = signature_path.read_text(encoding="utf-8").strip()

    if not verify_manifest_signature(manifest, signature, key):
        print(json.dumps({"status": "failed", "reason": "signature_mismatch"}))
        return 3

    ok, errors = verify_manifest_files(manifest)
    if not ok:
        print(json.dumps({"status": "failed", "reason": "artifact_mismatch", "errors": errors}))
        return 4

    print(json.dumps({"status": "ok", "verified_files": len(manifest.get("files", []))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
