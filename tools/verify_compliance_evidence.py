"""Verify signed compliance evidence bundle integrity."""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.evidence_export import resolve_signing_key_material, verify_evidence_file


def parse_args():
    p = argparse.ArgumentParser(description="Verify signed compliance evidence bundle.")
    p.add_argument(
        "--in",
        dest="in_path",
        default=str(ROOT / "artifacts" / "evidence" / "compliance_bundle.json"),
        help="Input JSON evidence bundle path.",
    )
    p.add_argument(
        "--key",
        default="",
        help="Signing key. If omitted, GUARDIAN_EVIDENCE_SIGNING_KEY is used.",
    )
    p.add_argument("--key-file", default="", help="Path to signing key file.")
    p.add_argument("--key-dir", default="", help="Directory containing rotation keys (*.key or *.txt).")
    p.add_argument("--key-provider", default="", help="Cloud key provider: aws-secretsmanager|azure-keyvault|gcp-secretmanager.")
    p.add_argument("--aws-secret-id", default="", help="AWS Secrets Manager secret id for signing key.")
    p.add_argument("--aws-region", default="", help="AWS region for Secrets Manager.")
    p.add_argument("--azure-vault-url", default="", help="Azure Key Vault URL.")
    p.add_argument("--azure-secret-name", default="", help="Azure Key Vault secret name.")
    p.add_argument("--azure-secret-version", default="", help="Azure Key Vault secret version (optional).")
    p.add_argument("--gcp-secret-resource", default="", help="GCP Secret Manager resource name.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.key_provider:
        os.environ["GUARDIAN_EVIDENCE_KEY_PROVIDER"] = args.key_provider
    if args.aws_secret_id:
        os.environ["GUARDIAN_EVIDENCE_AWS_SECRET_ID"] = args.aws_secret_id
    if args.aws_region:
        os.environ["GUARDIAN_EVIDENCE_AWS_REGION"] = args.aws_region
    if args.azure_vault_url:
        os.environ["GUARDIAN_EVIDENCE_AZURE_VAULT_URL"] = args.azure_vault_url
    if args.azure_secret_name:
        os.environ["GUARDIAN_EVIDENCE_AZURE_SECRET_NAME"] = args.azure_secret_name
    if args.azure_secret_version:
        os.environ["GUARDIAN_EVIDENCE_AZURE_SECRET_VERSION"] = args.azure_secret_version
    if args.gcp_secret_resource:
        os.environ["GUARDIAN_EVIDENCE_GCP_SECRET_RESOURCE"] = args.gcp_secret_resource

    key = args.key
    if not key and args.key_file:
        key = Path(args.key_file).read_text(encoding="utf-8").strip()
    if not key and args.key_dir:
        key_dir = Path(args.key_dir)
        if key_dir.exists():
            candidates = sorted(
                [p for p in key_dir.iterdir() if p.is_file() and p.suffix.lower() in {".key", ".txt"}],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for candidate in candidates:
                loaded = candidate.read_text(encoding="utf-8").strip()
                if loaded:
                    key = loaded
                    break
    if not key:
        key = os.environ.get("GUARDIAN_EVIDENCE_SIGNING_KEY", "").strip()
    if not key:
        key, _key_id = resolve_signing_key_material()
    if not key:
        print("Missing signing key. Provide --key or GUARDIAN_EVIDENCE_SIGNING_KEY.")
        return 2
    ok, message = verify_evidence_file(Path(args.in_path), key)
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
