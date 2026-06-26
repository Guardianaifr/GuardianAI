# Supply-Chain Hardening Validation Report

Date: March 18, 2026
Status: Completed

## Objective

Deliver baseline supply-chain controls for:

- SBOM generation
- dependency provenance/pinning visibility
- signed release artifact manifests
- signature and hash verification gate

## Implemented Controls

1. SBOM generation + provenance check

- Added `tools/generate_sbom.py`.
- Produces CycloneDX-style JSON output at `artifacts/supply_chain/sbom.json`.
- Includes requirements file SHA256 fingerprint.
- Reports unpinned dependencies and supports strict mode with `--enforce-pinned`.

2. Signed release manifests

- Added `tools/sign_release_artifacts.py`:
  - computes SHA256 manifest for release artifacts
  - signs manifest with HMAC key (`GUARDIAN_RELEASE_SIGNING_KEY`)

3. Verification gate

- Added `tools/verify_release_artifacts.py`:
  - verifies manifest signature
  - verifies each artifact hash against manifest

4. CI gate

- Added `.github/workflows/supply-chain-gate.yml` for PR checks:
  - SBOM generation
  - manifest signing
  - signature + hash verification

## Validation Results

Commands and outcomes:

- `pytest -q tests/security/test_supply_chain_hardening.py` -> `7 passed`
- `python tools/generate_sbom.py --requirements requirements.txt --output artifacts/supply_chain/sbom.json --model-manifest tests/data/model_manifest.json --enforce-pinned --enforce-model-provenance` -> `status: ok`, `all_dependencies_pinned: true`, `all_models_verified: true`
- `python tools/sign_release_artifacts.py ...` -> `status: ok`
- `python tools/verify_release_artifacts.py ...` -> `status: ok`, verified files: `3`
- `pytest -q` -> `241 passed`
- `python tools/run_missing_security_validation.py` -> passed (`sast_findings: 0`)
- `python tools/run_hardening_validation.py` -> completed (expected fixture findings present)
- `python tools/run_performance_chaos_validation.py` -> passed
- `python tools/check_security_slo.py` -> passed (`all_passed: true`)

## Current Risk Note

Dependency pinning is now enforced in `requirements.txt`, and SBOM strict gate (`--enforce-pinned`) passes in current validation.
