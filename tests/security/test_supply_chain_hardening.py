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

    report = verify_model_provenance(manifest)
    assert report["all_models_verified"] is True
    assert report["files_total"] == 1
    assert report["files_verified"] == 1


def test_model_provenance_detects_missing_file(tmp_path):
    manifest = tmp_path / "model_manifest.json"
    manifest.write_text(json.dumps({"missing-model.bin": "abc"}), encoding="utf-8")
    report = verify_model_provenance(manifest)
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
        ],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 3
