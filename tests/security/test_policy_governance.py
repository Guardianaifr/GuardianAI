from pathlib import Path

import yaml

from security.policy_governance import compute_config_integrity_hash, evaluate_policy_governance


def _write_yaml(path: Path, data: dict):
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _base_config() -> dict:
    return {
        "governance": {
            "enabled": True,
            "mode": "enforce",
        },
        "security_policies": {
            "security_mode": "balanced",
            "leak_prevention_strategy": "block",
        },
        "rate_limiting": {"requests_per_minute": 60},
        "backend": {"enabled": True},
    }


def test_enforce_blocks_high_risk_without_approval(tmp_path: Path):
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "enforce"})

    allowed, findings = evaluate_policy_governance(config, config_path, policy_path)
    assert allowed is False
    assert any(f.code == "approval_required" for f in findings)


def test_enforce_allows_high_risk_with_valid_approval_hash(tmp_path: Path):
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config_path = tmp_path / "config.yaml"
    _write_yaml(config_path, config)
    config["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "SEC-42",
        "config_sha256": "",
    }
    _write_yaml(config_path, config)
    cfg_hash = compute_config_integrity_hash(config_path)
    config["governance"]["approval"]["config_sha256"] = cfg_hash
    _write_yaml(config_path, config)

    policy_path = tmp_path / "policy.yaml"
    _write_yaml(policy_path, {"mode": "enforce"})
    allowed, findings = evaluate_policy_governance(config, config_path, policy_path)
    assert allowed is True
    assert findings == []


def test_enforce_blocks_on_hash_mismatch(tmp_path: Path):
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "SEC-77",
        "config_sha256": "0" * 64,
    }
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "enforce"})

    allowed, findings = evaluate_policy_governance(config, config_path, policy_path)
    assert allowed is False
    assert any(f.code == "config_integrity_mismatch" for f in findings)


def test_audit_mode_reports_but_does_not_block(tmp_path: Path):
    config = _base_config()
    config["governance"]["mode"] = "audit"
    config["security_policies"]["security_mode"] = "lenient"
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "audit"})

    allowed, findings = evaluate_policy_governance(config, config_path, policy_path)
    assert allowed is True
    assert any(f.code == "approval_required" for f in findings)
