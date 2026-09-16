"""Compliance evidence export utilities."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import hmac
import json
import os
import platform
import subprocess
from typing import Any

import yaml

try:
    from guardian.security.policy_governance import compute_config_integrity_hash
except ImportError:
    try:
        from .policy_governance import compute_config_integrity_hash
    except ImportError:
        from security.policy_governance import compute_config_integrity_hash


@dataclass
class EvidenceBundle:
    generated_at_utc: str
    project_root: str
    python_version: str
    platform: str
    git_commit: str
    git_dirty: bool
    config_path: str
    config_integrity_sha256: str
    policy_mode: str
    validation: dict[str, Any]
    signature: str
    signature_algorithm: str
    signature_key_id: str


def _git_value(root: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _canonical_payload(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_evidence_payload(data: dict[str, Any], signing_key: str) -> str:
    payload = _canonical_payload(data)
    digest = hmac.new(signing_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return digest


def verify_evidence_payload_signature(data: dict[str, Any], signing_key: str, expected_signature: str) -> bool:
    actual = sign_evidence_payload(data, signing_key)
    return hmac.compare_digest(actual, expected_signature)


def _extract_last_json_object(text: str) -> dict[str, Any]:
    """Extract last JSON object from mixed log output."""
    end = text.rfind("}")
    if end < 0:
        raise ValueError("No JSON object found in output")
    start = text.rfind("{", 0, end + 1)
    while start >= 0:
        fragment = text[start : end + 1]
        try:
            data = json.loads(fragment)
            if isinstance(data, dict):
                return data
        except Exception:  # noqa: BLE001
            pass
        start = text.rfind("{", 0, start)
    raise ValueError("Could not parse JSON object from output")


def _run_validation_script(python_exe: str, root: Path, script_rel: str) -> dict[str, Any]:
    proc = subprocess.run(
        [python_exe, str(root / script_rel)],
        capture_output=True,
        text=True,
        check=False,
    )
    out = proc.stdout.strip()
    err = proc.stderr.strip()
    parsed: dict[str, Any] = {}
    if out:
        parsed = _extract_last_json_object(out)
    return {
        "script": script_rel,
        "exit_code": proc.returncode,
        "report": parsed,
        "stderr": err[-2000:] if err else "",
    }


def _discover_config(root: Path) -> Path:
    for rel in ["guardian/config/wizard_config.yaml", "guardian/config/config.yaml"]:
        path = root / rel
        if path.exists():
            return path
    raise FileNotFoundError("No Guardian config file found")


def _load_key_from_file(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def _load_from_aws_secrets_manager(secret_id: str, region: str) -> str:
    try:
        import boto3  # type: ignore
    except Exception:
        return ""
    try:
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=secret_id)
        secret_string = response.get("SecretString", "")
        if isinstance(secret_string, str):
            return secret_string.strip()
        secret_binary = response.get("SecretBinary")
        if isinstance(secret_binary, (bytes, bytearray)):
            return bytes(secret_binary).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""
    return ""


def _load_from_azure_key_vault(vault_url: str, secret_name: str, secret_version: str = "") -> str:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.keyvault.secrets import SecretClient  # type: ignore
    except Exception:
        return ""
    try:
        client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
        kv_result = client.get_secret(secret_name, secret_version=secret_version or None)
        value = getattr(kv_result, "value", "")
        if isinstance(value, str):
            return value.strip()
    except Exception:
        return ""
    return ""


def _load_from_gcp_secret_manager(secret_resource: str) -> str:
    try:
        from google.cloud import secretmanager  # type: ignore
    except Exception:
        return ""
    try:
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(request={"name": secret_resource})
        payload = getattr(response, "payload", None)
        data = getattr(payload, "data", b"")
        if isinstance(data, (bytes, bytearray)):
            return bytes(data).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""
    return ""


def _resolve_cloud_key_provider(explicit_key_id: str) -> tuple[str, str]:
    provider = os.environ.get("GUARDIAN_EVIDENCE_KEY_PROVIDER", "").strip().lower()
    if not provider:
        return "", ""

    if provider in {"aws", "aws-secretsmanager", "aws_sm"}:
        secret_id = os.environ.get("GUARDIAN_EVIDENCE_AWS_SECRET_ID", "").strip()
        region = os.environ.get("GUARDIAN_EVIDENCE_AWS_REGION", "").strip() or "us-east-1"
        if not secret_id:
            return "", ""
        key = _load_from_aws_secrets_manager(secret_id, region)
        if key:
            return key, (explicit_key_id or f"aws:{secret_id}")
        return "", ""

    if provider in {"azure", "azure-keyvault", "azure_kv"}:
        vault_url = os.environ.get("GUARDIAN_EVIDENCE_AZURE_VAULT_URL", "").strip()
        secret_name = os.environ.get("GUARDIAN_EVIDENCE_AZURE_SECRET_NAME", "").strip()
        secret_version = os.environ.get("GUARDIAN_EVIDENCE_AZURE_SECRET_VERSION", "").strip()
        if not vault_url or not secret_name:
            return "", ""
        key = _load_from_azure_key_vault(vault_url, secret_name, secret_version)
        if key:
            return key, (explicit_key_id or f"azure:{secret_name}")
        return "", ""

    if provider in {"gcp", "gcp-secretmanager", "gcp_sm"}:
        secret_resource = os.environ.get("GUARDIAN_EVIDENCE_GCP_SECRET_RESOURCE", "").strip()
        if not secret_resource:
            return "", ""
        key = _load_from_gcp_secret_manager(secret_resource)
        if key:
            return key, (explicit_key_id or f"gcp:{secret_resource}")
        return "", ""

    return "", ""


def resolve_signing_key_material() -> tuple[str, str]:
    """Resolve signing key and key-id with production-friendly precedence.

    Precedence:
    1) GUARDIAN_EVIDENCE_SIGNING_KEY
    2) Cloud key provider (AWS/Azure/GCP) via GUARDIAN_EVIDENCE_KEY_PROVIDER
    3) GUARDIAN_EVIDENCE_SIGNING_KEY_FILE
    4) Latest key in GUARDIAN_EVIDENCE_SIGNING_KEY_DIR (*.key, *.txt)
    """
    key = os.environ.get("GUARDIAN_EVIDENCE_SIGNING_KEY", "").strip()
    key_id = os.environ.get("GUARDIAN_EVIDENCE_SIGNING_KEY_ID", "").strip()
    if key:
        return key, (key_id or "env")

    cloud_key, cloud_key_id = _resolve_cloud_key_provider(key_id)
    if cloud_key:
        return cloud_key, cloud_key_id

    key_file_raw = os.environ.get("GUARDIAN_EVIDENCE_SIGNING_KEY_FILE", "").strip()
    if key_file_raw:
        key_path = Path(key_file_raw)
        loaded = _load_key_from_file(key_path)
        if loaded:
            if not key_id:
                key_id = key_path.stem
            return loaded, key_id or "file"

    key_dir_raw = os.environ.get("GUARDIAN_EVIDENCE_SIGNING_KEY_DIR", "").strip()
    if key_dir_raw:
        key_dir = Path(key_dir_raw)
        if key_dir.exists():
            candidates = sorted(
                [p for p in key_dir.iterdir() if p.is_file() and p.suffix.lower() in {".key", ".txt"}],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for candidate in candidates:
                loaded = _load_key_from_file(candidate)
                if loaded:
                    if not key_id:
                        key_id = candidate.stem
                    return loaded, key_id or "dir-latest"

    return "", ""


def build_evidence_bundle(root: Path, python_exe: str, include_validation: bool = True) -> EvidenceBundle:
    project_root = Path(root).resolve()
    config_path = _discover_config(project_root)
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    governance_mode = str((cfg.get("governance", {}) or {}).get("mode", "disabled")).lower()

    validation: dict[str, Any] = {}
    if include_validation:
        validation["missing_security_validation"] = _run_validation_script(
            python_exe, project_root, "tools/run_missing_security_validation.py"
        )
        validation["hardening_validation"] = _run_validation_script(
            python_exe, project_root, "tools/run_hardening_validation.py"
        )

    commit = _git_value(project_root, ["rev-parse", "HEAD"])
    dirty = bool(_git_value(project_root, ["status", "--porcelain"]))

    key, key_id = resolve_signing_key_material()

    unsigned = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "project_root": str(project_root).replace("\\", "/"),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "git_commit": commit or "unknown",
        "git_dirty": dirty,
        "config_path": str(config_path).replace("\\", "/"),
        "config_integrity_sha256": compute_config_integrity_hash(config_path),
        "policy_mode": governance_mode,
        "validation": validation,
    }
    signature = sign_evidence_payload(unsigned, key) if key else ""

    bundle = EvidenceBundle(
        generated_at_utc=unsigned["generated_at_utc"],
        project_root=unsigned["project_root"],
        python_version=unsigned["python_version"],
        platform=unsigned["platform"],
        git_commit=unsigned["git_commit"],
        git_dirty=unsigned["git_dirty"],
        config_path=unsigned["config_path"],
        config_integrity_sha256=unsigned["config_integrity_sha256"],
        policy_mode=unsigned["policy_mode"],
        validation=unsigned["validation"],
        signature=signature,
        signature_algorithm="hmac-sha256" if key else "none",
        signature_key_id=key_id if key else "",
    )
    return bundle


def write_evidence_bundle(root: Path, python_exe: str, out_path: Path, include_validation: bool = True) -> Path:
    bundle = build_evidence_bundle(root, python_exe, include_validation=include_validation)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(asdict(bundle), indent=2), encoding="utf-8")
    return out


def verify_evidence_file(path: Path, signing_key: str) -> tuple[bool, str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("signature_algorithm") != "hmac-sha256":
        return False, "Unsupported or missing signature algorithm"
    sig = str(payload.get("signature", "")).strip()
    if not sig:
        return False, "Missing signature"

    signed_data = dict(payload)
    signed_data.pop("signature", None)
    signed_data.pop("signature_algorithm", None)
    signed_data.pop("signature_key_id", None)

    ok = verify_evidence_payload_signature(signed_data, signing_key, sig)
    return (ok, "ok" if ok else "Signature mismatch")
