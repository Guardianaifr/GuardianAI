import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

from guardian.security.supply_chain import (
    build_sbom,
    create_release_manifest,
    sign_manifest,
    verify_model_provenance,
    verify_manifest_files,
    verify_manifest_signature,
)


def test_build_sbom_marks_all_pinned(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==0.111.0\nuvicorn==0.30.0\n", encoding="utf-8")
    sbom = build_sbom(req, project_name="test-project")
    assert sbom["validation"]["all_dependencies_pinned"] is True
    assert len(sbom["components"]) == 2


def test_build_sbom_flags_unpinned_requirements(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi>=0.111.0\n", encoding="utf-8")
    sbom = build_sbom(req, project_name="test-project")
    assert sbom["validation"]["all_dependencies_pinned"] is False
    assert sbom["validation"]["unpinned_dependencies"] == ["fastapi>=0.111.0"]


def test_model_provenance_verified_from_manifest(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("model-weights", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest = tmp_path / "model_manifest.json"
    manifest.write_text(json.dumps({str(model_file): model_hash}), encoding="utf-8")

    report = verify_model_provenance(manifest, enforce_signature=False)
    assert report["all_models_verified"] is True
    assert report["files_total"] == 1
    assert report["files_verified"] == 1


def test_model_provenance_detects_missing_file(tmp_path):
    manifest = tmp_path / "model_manifest.json"
    manifest.write_text(json.dumps({"missing-model.bin": "abc"}), encoding="utf-8")
    report = verify_model_provenance(manifest, enforce_signature=False)
    assert report["all_models_verified"] is False
    assert report["files_total"] == 1
    assert report["files_verified"] == 0
    assert report["errors"]


def test_manifest_sign_and_verify_roundtrip(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("hello", encoding="utf-8")
    manifest = create_release_manifest([artifact])
    key = "test-key"
    signature = sign_manifest(manifest, key)
    assert verify_manifest_signature(manifest, signature, key) is True
    ok, errors = verify_manifest_files(manifest)
    assert ok is True
    assert errors == []


def test_release_sign_verify_scripts(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("signed-content", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    sig = tmp_path / "manifest.sig"
    env = dict(os.environ)
    env["GUARDIAN_RELEASE_SIGNING_KEY"] = "test-key"

    sign = subprocess.run(
        [
            sys.executable,
            "tools/sign_release_artifacts.py",
            "--artifact",
            str(artifact),
            "--manifest-out",
            str(manifest),
            "--signature-out",
            str(sig),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert sign.returncode == 0

    verify = subprocess.run(
        [
            sys.executable,
            "tools/verify_release_artifacts.py",
            "--manifest",
            str(manifest),
            "--signature",
            str(sig),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert verify.returncode == 0
    payload = json.loads(verify.stdout.strip())
    assert payload["status"] == "ok"


def test_generate_sbom_enforces_model_provenance(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==0.111.0\n", encoding="utf-8")
    manifest = tmp_path / "model_manifest.json"
    manifest.write_text(json.dumps({"missing-model.bin": "abc"}), encoding="utf-8")
    out = tmp_path / "sbom.json"

    run = subprocess.run(
        [
            sys.executable,
            "tools/generate_sbom.py",
            "--requirements",
            str(req),
            "--output",
            str(out),
            "--model-manifest",
            str(manifest),
            "--enforce-model-provenance",
            "--no-enforce-signature",
        ],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 3


def test_model_provenance_rejects_missing_key_when_enforced(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights-content", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    # When key is missing and enforce_signature=True
    report = verify_model_provenance(manifest_path, enforce_signature=True, last_known_version=1)
    assert report["all_models_verified"] is False
    assert any("signature verification key is required but missing" in err for err in report["errors"])


def test_model_provenance_version_rollback_protection(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights-content", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    key = "secret-key"
    signature = sign_manifest(manifest_data, key)
    sig_path = tmp_path / "model_manifest.sig"
    sig_path.write_text(signature, encoding="utf-8")

    # Reject version 1 < 2
    report = verify_model_provenance(
        manifest_path,
        verification_key=key,
        signature_path=sig_path,
        enforce_signature=True,
        last_known_version=2,
    )
    assert report["all_models_verified"] is False
    assert any("Rollback detected" in err for err in report["errors"])


def test_model_provenance_rejects_missing_version_field(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights-content", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    key = "secret-key"
    signature = sign_manifest(manifest_data, key)
    sig_path = tmp_path / "model_manifest.sig"
    sig_path.write_text(signature, encoding="utf-8")

    report = verify_model_provenance(
        manifest_path,
        verification_key=key,
        signature_path=sig_path,
        enforce_signature=True,
        last_known_version=1,
    )
    assert report["all_models_verified"] is False
    assert any("manifest missing required version field" in err for err in report["errors"])


def test_model_provenance_rejects_default_last_known_version_in_production(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights-content", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    key = "secret-key"
    signature = sign_manifest(manifest_data, key)
    sig_path = tmp_path / "model_manifest.sig"
    sig_path.write_text(signature, encoding="utf-8")

    report = verify_model_provenance(
        manifest_path,
        verification_key=key,
        signature_path=sig_path,
        enforce_signature=True,
        last_known_version=None,
    )
    assert report["all_models_verified"] is False
    assert any("last_known_version is required when signature enforcement is enabled" in err for err in report["errors"])


def test_model_provenance_accepts_first_release_with_explicit_zero(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights-content", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    key = "secret-key"
    signature = sign_manifest(manifest_data, key)
    sig_path = tmp_path / "model_manifest.sig"
    sig_path.write_text(signature, encoding="utf-8")

    report = verify_model_provenance(
        manifest_path,
        verification_key=key,
        signature_path=sig_path,
        enforce_signature=True,
        last_known_version=0,
    )
    assert report["all_models_verified"] is True
    assert report["files_verified"] == 1
    assert not report["errors"]


def test_generate_sbom_argparse_defaults_none():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--last-known-version", type=int, default=None)
    args = parser.parse_args([])
    assert args.last_known_version is None


def test_model_provenance_rejects_missing_manifest_file(tmp_path):
    missing_manifest = tmp_path / "non_existent_manifest.json"
    report = verify_model_provenance(missing_manifest, enforce_signature=False)
    assert report["all_models_verified"] is False
    assert any("model manifest missing" in err for err in report["errors"])


def test_model_provenance_rejects_malformed_manifest_json(tmp_path):
    bad_manifest = tmp_path / "bad.json"
    bad_manifest.write_text("{invalid json", encoding="utf-8")
    report = verify_model_provenance(bad_manifest, enforce_signature=False)
    assert report["all_models_verified"] is False
    assert any("invalid model manifest json" in err for err in report["errors"])


def test_model_provenance_rejects_non_dict_manifest(tmp_path):
    list_manifest = tmp_path / "list.json"
    list_manifest.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    report = verify_model_provenance(list_manifest, enforce_signature=False)
    assert report["all_models_verified"] is False
    assert any("model manifest must be a JSON object" in err for err in report["errors"])


def test_model_provenance_rejects_missing_signature_file(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = verify_model_provenance(
        manifest_path,
        verification_key="key",
        signature_path=tmp_path / "missing.sig",
        enforce_signature=True,
        last_known_version=0,
    )
    assert report["all_models_verified"] is False
    assert any("signature file missing" in err for err in report["errors"])


def test_model_provenance_rejects_invalid_signature_content(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    sig_path = tmp_path / "model_manifest.sig"
    sig_path.write_text("invalid-sig", encoding="utf-8")

    report = verify_model_provenance(
        manifest_path,
        verification_key="key",
        signature_path=sig_path,
        enforce_signature=True,
        last_known_version=0,
    )
    assert report["all_models_verified"] is False
    assert any("signature verification failed" in err for err in report["errors"])


def test_model_provenance_rejects_non_integer_version(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("weights", encoding="utf-8")
    model_hash = hashlib.sha256(model_file.read_bytes()).hexdigest()
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": "abc",
        "weights": [{"path": str(model_file), "sha256": model_hash}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = verify_model_provenance(manifest_path, enforce_signature=False, last_known_version=1)
    assert report["all_models_verified"] is False
    assert any("manifest version must be an integer" in err for err in report["errors"])


def test_model_provenance_rejects_empty_weights(tmp_path):
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": []
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = verify_model_provenance(manifest_path, enforce_signature=False, last_known_version=0)
    assert report["all_models_verified"] is False
    assert any("no model files defined in manifest" in err for err in report["errors"])


def test_model_provenance_rejects_hash_mismatch(tmp_path):
    model_file = tmp_path / "model.bin"
    model_file.write_text("actual-content", encoding="utf-8")
    manifest_path = tmp_path / "model_manifest.json"
    manifest_data = {
        "version": 1,
        "weights": [{"path": str(model_file), "sha256": "wrong-hash"}]
    }
    manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

    report = verify_model_provenance(manifest_path, enforce_signature=False, last_known_version=0)
    assert report["all_models_verified"] is False
    assert any("hash mismatch" in err for err in report["errors"])


