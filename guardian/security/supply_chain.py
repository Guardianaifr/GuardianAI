"""Supply-chain hardening helpers: SBOM, manifests, and artifact signatures."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
import time
from typing import Any


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_requirements(requirements_path: Path) -> tuple[list[dict[str, str]], list[str]]:
    components: list[dict[str, str]] = []
    unpinned: list[str] = []
    for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            components.append(
                {
                    "name": name.strip(),
                    "version": version.strip(),
                    "purl": f"pkg:pypi/{name.strip()}@{version.strip()}",
                }
            )
        else:
            unpinned.append(line)
    return components, unpinned


def _normalize_model_entries(manifest: dict[str, Any]) -> tuple[list[dict[str, str]], dict[str, Any]]:
    # Legacy/simple format: {"path/to/model.bin":"<sha256>"}
    if all(isinstance(v, str) for v in manifest.values()) and all(isinstance(k, str) for k in manifest.keys()):
        entries = [{"path": str(k), "sha256": str(v)} for k, v in manifest.items()]
        meta = {"model_id": "", "provider": "", "source_uri": ""}
        return entries, meta

    entries: list[dict[str, str]] = []
    for item in manifest.get("weights", []) or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        sha256 = str(item.get("sha256", "")).strip()
        if path and sha256:
            entries.append({"path": path, "sha256": sha256})
    meta = {
        "model_id": str(manifest.get("model_id", "")).strip(),
        "provider": str(manifest.get("provider", "")).strip(),
        "source_uri": str(manifest.get("source_uri", "")).strip(),
    }
    return entries, meta


def verify_model_provenance(
    model_manifest_path: Path,
    verification_key: str | None = None,
    signature_path: Path | None = None,
    enforce_signature: bool = True,
    last_known_version: int | None = None,
) -> dict[str, Any]:
    import os
    report: dict[str, Any] = {
        "enabled": True,
        "manifest_path": str(model_manifest_path),
        "model_id": "",
        "provider": "",
        "source_uri": "",
        "all_models_verified": False,
        "files_total": 0,
        "files_verified": 0,
        "errors": [],
    }
    if not model_manifest_path.exists():
        report["errors"].append(f"model manifest missing: {model_manifest_path}")
        return report

    try:
        manifest = json.loads(model_manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        report["errors"].append(f"invalid model manifest json: {exc}")
        return report

    if not isinstance(manifest, dict):
        report["errors"].append("model manifest must be a JSON object")
        return report

    # 1. Enforce signature validation
    if enforce_signature:
        if last_known_version is None:
            report["errors"].append("last_known_version is required when signature enforcement is enabled")
            return report

        signing_key = verification_key or os.environ.get("GUARDIAN_RELEASE_SIGNING_KEY", "").strip()
        if not signing_key:
            report["errors"].append("signature verification key is required but missing")
            return report

        sig_file = signature_path or model_manifest_path.with_suffix(".sig")
        if not sig_file.exists():
            report["errors"].append(f"signature file missing: {sig_file}")
            return report
        try:
            signature_b64 = sig_file.read_text(encoding="utf-8").strip()
        except Exception as exc:
            report["errors"].append(f"failed to read signature file: {exc}")
            return report

        if not verify_manifest_signature(manifest, signature_b64, signing_key):
            report["errors"].append("manifest signature verification failed: signature mismatch")
            return report

    # 2. Decoupled rollback and version field validation
    if enforce_signature or last_known_version is not None:
        if "version" not in manifest:
            report["errors"].append("manifest missing required version field")
            return report
        try:
            version_val = int(manifest["version"])
        except (ValueError, TypeError):
            report["errors"].append("manifest version must be an integer")
            return report

        if last_known_version is not None and version_val < last_known_version:
            report["errors"].append(f"Rollback detected: manifest version {version_val} < last_known_version {last_known_version}")
            return report

    entries, meta = _normalize_model_entries(manifest)
    report.update(meta)
    report["files_total"] = len(entries)
    if not entries:
        report["errors"].append("no model files defined in manifest")
        return report

    verified = 0
    for entry in entries:
        raw_path = Path(entry["path"])
        if raw_path.is_absolute():
            file_path = raw_path
        else:
            candidate_from_manifest = (model_manifest_path.parent / raw_path)
            file_path = candidate_from_manifest if candidate_from_manifest.exists() else raw_path
        if not file_path.exists():
            report["errors"].append(f"missing model artifact: {file_path}")
            continue
        actual = _sha256_file(file_path)
        if actual != entry["sha256"]:
            report["errors"].append(f"hash mismatch: {file_path}")
            continue
        verified += 1

    report["files_verified"] = verified
    report["all_models_verified"] = verified == report["files_total"] and len(report["errors"]) == 0
    return report


def build_sbom(
    requirements_path: Path,
    project_name: str = "guardianai-basic-launch",
    model_manifest_path: Path | None = None,
    verification_key: str | None = None,
    signature_path: Path | None = None,
    enforce_signature: bool = True,
    last_known_version: int | None = None,
) -> dict[str, Any]:
    components, unpinned = parse_requirements(requirements_path)
    model_provenance = (
        verify_model_provenance(
            model_manifest_path,
            verification_key=verification_key,
            signature_path=signature_path,
            enforce_signature=enforce_signature,
            last_known_version=last_known_version,
        ) if model_manifest_path else {
            "enabled": False,
            "manifest_path": "",
            "model_id": "",
            "provider": "",
            "source_uri": "",
            "all_models_verified": True,
            "files_total": 0,
            "files_verified": 0,
            "errors": [],
        }
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "component": {"type": "application", "name": project_name},
            "source_requirements": str(requirements_path),
            "source_requirements_sha256": _sha256_file(requirements_path),
        },
        "components": components,
        "validation": {
            "all_dependencies_pinned": len(unpinned) == 0,
            "unpinned_dependencies": unpinned,
            "model_provenance": model_provenance,
        },
    }


def create_release_manifest(artifacts: list[Path], version: int = 1) -> dict[str, Any]:
    normalized = sorted({str(path) for path in artifacts})
    files: list[dict[str, Any]] = []
    for item in normalized:
        path = Path(item)
        files.append(
            {
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return {
        "version": version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "algorithm": "sha256",
        "files": files,
    }


def sign_manifest(manifest: dict[str, Any], key: str) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    signature = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).digest()
    return base64.b64encode(signature).decode("ascii")


def verify_manifest_signature(manifest: dict[str, Any], signature_b64: str, key: str) -> bool:
    expected = sign_manifest(manifest, key)
    return hmac.compare_digest(expected, signature_b64.strip())


def verify_manifest_files(manifest: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for file_record in manifest.get("files", []):
        path = Path(file_record.get("path", ""))
        expected_hash = str(file_record.get("sha256", ""))
        if not path.exists():
            errors.append(f"missing file: {path}")
            continue
        actual_hash = _sha256_file(path)
        if actual_hash != expected_hash:
            errors.append(f"hash mismatch: {path}")
    return len(errors) == 0, errors
