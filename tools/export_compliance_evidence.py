"""Export machine-readable compliance evidence bundle."""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.evidence_export import write_evidence_bundle


def parse_args():
    p = argparse.ArgumentParser(description="Export compliance evidence bundle.")
    p.add_argument(
        "--out",
        default=str(ROOT / "artifacts" / "evidence" / "compliance_bundle.json"),
        help="Output JSON path.",
    )
    p.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip running validation scripts in the bundle generation step.",
    )
    p.add_argument("--key", default="", help="Signing key value (overrides other key sources).")
    p.add_argument("--key-file", default="", help="Path to signing key file.")
    p.add_argument("--key-dir", default="", help="Directory containing rotation keys (*.key or *.txt).")
    p.add_argument("--key-id", default="", help="Signing key identifier override.")
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
    if args.key:
        os.environ["GUARDIAN_EVIDENCE_SIGNING_KEY"] = args.key
    if args.key_file:
        os.environ["GUARDIAN_EVIDENCE_SIGNING_KEY_FILE"] = args.key_file
    if args.key_dir:
        os.environ["GUARDIAN_EVIDENCE_SIGNING_KEY_DIR"] = args.key_dir
    if args.key_id:
        os.environ["GUARDIAN_EVIDENCE_SIGNING_KEY_ID"] = args.key_id
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
    python_exe = sys.executable
    out = write_evidence_bundle(
        ROOT,
        python_exe,
        Path(args.out),
        include_validation=not args.skip_validation,
    )
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
