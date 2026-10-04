from pathlib import Path
import json
import os
import time

import security.evidence_export as evidence_export
from security.evidence_export import (
    _extract_last_json_object,
    resolve_signing_key_material,
    verify_evidence_file,
    write_evidence_bundle,
)


def test_extract_last_json_object_from_mixed_logs():
    text = "INFO start\n{ \"a\": 1 }\nINFO middle\n{ \"b\": 2, \"c\": 3 }\n"
    data = _extract_last_json_object(text)
    assert data["b"] == 2
    assert data["c"] == 3


def test_write_evidence_bundle_without_validation(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    out = tmp_path / "bundle.json"
    path = write_evidence_bundle(root, "python", out, include_validation=False)
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert Path(payload["project_root"]).name == root.name  # checkout dir name differs in CI
    assert payload["config_integrity_sha256"]
    assert "validation" in payload
    assert payload["validation"] == {}


def test_signed_evidence_verification_detects_tamper(tmp_path: Path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    out = tmp_path / "bundle.json"
    monkeypatch.setenv("GUARDIAN_EVIDENCE_SIGNING_KEY", "unit-test-signing-key")
    write_evidence_bundle(root, "python", out, include_validation=False)

    ok, message = verify_evidence_file(out, "unit-test-signing-key")
    assert ok is True
    assert message == "ok"

    payload = json.loads(out.read_text(encoding="utf-8"))
    payload["git_commit"] = "tampered"
    out.write_text(json.dumps(payload), encoding="utf-8")

    ok2, message2 = verify_evidence_file(out, "unit-test-signing-key")
    assert ok2 is False
    assert "mismatch" in message2.lower()


def test_resolve_signing_key_from_key_file(tmp_path: Path, monkeypatch):
    key_file = tmp_path / "guardian-prod.key"
    key_file.write_text("file-key-material", encoding="utf-8")
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("GUARDIAN_EVIDENCE_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_DIR", raising=False)
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_ID", raising=False)

    key, key_id = resolve_signing_key_material()
    assert key == "file-key-material"
    assert key_id == "guardian-prod"


def test_resolve_signing_key_from_latest_rotation_dir(tmp_path: Path, monkeypatch):
    old_key = tmp_path / "rotation-001.key"
    new_key = tmp_path / "rotation-002.key"
    old_key.write_text("old-key", encoding="utf-8")
    new_key.write_text("new-key", encoding="utf-8")

    # Ensure deterministic mtime order.
    now = time.time()
    os.utime(old_key, (now - 20, now - 20))
    os.utime(new_key, (now - 1, now - 1))

    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setenv("GUARDIAN_EVIDENCE_SIGNING_KEY_DIR", str(tmp_path))
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_ID", raising=False)

    key, key_id = resolve_signing_key_material()
    assert key == "new-key"
    assert key_id == "rotation-002"


def test_resolve_signing_key_from_aws_provider(monkeypatch):
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_FILE", raising=False)
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_DIR", raising=False)
    monkeypatch.setenv("GUARDIAN_EVIDENCE_KEY_PROVIDER", "aws-secretsmanager")
    monkeypatch.setenv("GUARDIAN_EVIDENCE_AWS_SECRET_ID", "guardian/prod/signing")
    monkeypatch.setenv("GUARDIAN_EVIDENCE_AWS_REGION", "us-east-1")
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_ID", raising=False)
    monkeypatch.setattr(evidence_export, "_load_from_aws_secrets_manager", lambda *_args, **_kwargs: "aws-key")

    key, key_id = resolve_signing_key_material()
    assert key == "aws-key"
    assert key_id == "aws:guardian/prod/signing"


def test_resolve_signing_key_from_azure_provider(monkeypatch):
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("GUARDIAN_EVIDENCE_KEY_PROVIDER", "azure-keyvault")
    monkeypatch.setenv("GUARDIAN_EVIDENCE_AZURE_VAULT_URL", "https://example.vault.azure.net")
    monkeypatch.setenv("GUARDIAN_EVIDENCE_AZURE_SECRET_NAME", "guardian-signing")
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_ID", raising=False)
    monkeypatch.setattr(evidence_export, "_load_from_azure_key_vault", lambda *_args, **_kwargs: "azure-key")

    key, key_id = resolve_signing_key_material()
    assert key == "azure-key"
    assert key_id == "azure:guardian-signing"


def test_resolve_signing_key_from_gcp_provider(monkeypatch):
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY", raising=False)
    monkeypatch.setenv("GUARDIAN_EVIDENCE_KEY_PROVIDER", "gcp-secretmanager")
    monkeypatch.setenv(
        "GUARDIAN_EVIDENCE_GCP_SECRET_RESOURCE",
        "projects/demo/secrets/guardian-signing/versions/latest",
    )
    monkeypatch.delenv("GUARDIAN_EVIDENCE_SIGNING_KEY_ID", raising=False)
    monkeypatch.setattr(evidence_export, "_load_from_gcp_secret_manager", lambda *_args, **_kwargs: "gcp-key")

    key, key_id = resolve_signing_key_material()
    assert key == "gcp-key"
    assert key_id.startswith("gcp:projects/demo/secrets/guardian-signing")
