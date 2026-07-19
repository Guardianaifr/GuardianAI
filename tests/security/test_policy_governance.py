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

    allowed, findings = evaluate_policy_governance(config, config_path, policy_path, require_signature=False, require_baseline=False, db_path=tmp_path / "tickets.db")
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
    allowed, findings = evaluate_policy_governance(config, config_path, policy_path, require_signature=False, require_baseline=False, db_path=tmp_path / "tickets.db")
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

    allowed, findings = evaluate_policy_governance(config, config_path, policy_path, require_signature=False, require_baseline=False, db_path=tmp_path / "tickets.db")
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

    allowed, findings = evaluate_policy_governance(config, config_path, policy_path, require_signature=False, require_baseline=False, db_path=tmp_path / "tickets.db")
    assert allowed is True
    assert any(f.code == "approval_required" for f in findings)


# ── Hardened Ed25519 & Nonce Regression Tests ────────────────────────

import base64
import time
import sqlite3
from cryptography.hazmat.primitives.asymmetric import ed25519

def _generate_ed25519_keypair():
    privkey = ed25519.Ed25519PrivateKey.generate()
    pubkey = privkey.public_key()
    pubkey_b64 = base64.b64encode(pubkey.public_bytes_raw()).decode("ascii")
    return privkey, pubkey_b64


def _sign_approval(privkey, approver: str, ticket: str, config_sha256: str) -> str:
    payload = f"{approver}:{ticket}:{config_sha256}".encode("utf-8")
    sig_bytes = privkey.sign(payload)
    return base64.b64encode(sig_bytes).decode("ascii")


def test_governance_rejects_missing_public_key_when_enforced(tmp_path: Path):
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "SEC-42",
        "config_sha256": "0" * 64,
        "signature": "some-sig",
    }
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        public_key_b64=None,
        require_signature=True,
        require_baseline=False,
        db_path=tmp_path / "tickets.db",
    )
    assert allowed is False
    assert any(f.code == "public_key_missing" for f in findings)


def test_governance_rejects_invalid_ed25519_signature(tmp_path: Path):
    _, pubkey_b64 = _generate_ed25519_keypair()
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "SEC-42",
        "config_sha256": "0" * 64,
        "signature": base64.b64encode(b"invalid-signature-bytes").decode("ascii"),
    }
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "enforce"})

    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        public_key_b64=pubkey_b64,
        require_signature=True,
        require_baseline=False,
        db_path=tmp_path / "tickets.db",
    )
    assert allowed is False
    assert any(f.code == "invalid_approval_signature" for f in findings)


def test_governance_accepts_valid_ed25519_signature(tmp_path: Path):
    privkey, pubkey_b64 = _generate_ed25519_keypair()
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config_path = tmp_path / "config.yaml"
    config["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "SEC-42",
        "config_sha256": "",
        "signature": "",
    }
    _write_yaml(config_path, config)

    cfg_hash = compute_config_integrity_hash(config_path)
    sig = _sign_approval(privkey, "sec-team", "SEC-42", cfg_hash)

    config["governance"]["approval"]["config_sha256"] = cfg_hash
    config["governance"]["approval"]["signature"] = sig
    _write_yaml(config_path, config)

    policy_path = tmp_path / "policy.yaml"
    _write_yaml(policy_path, {"mode": "enforce"})
    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        public_key_b64=pubkey_b64,
        require_signature=True,
        require_baseline=False,
        db_path=tmp_path / "tickets.db",
    )
    assert allowed is True
    assert not findings


def test_governance_ticket_replay_prevention_sqlite(tmp_path: Path):
    privkey, pubkey_b64 = _generate_ed25519_keypair()
    db_file = tmp_path / "tickets.db"

    # 1. Prepare and approve config 1
    config1 = _base_config()
    config1["security_policies"]["security_mode"] = "lenient"
    config_path1 = tmp_path / "config1.yaml"
    config1["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "REPLAY-1",
        "config_sha256": "",
        "signature": "",
    }
    _write_yaml(config_path1, config1)

    cfg_hash1 = compute_config_integrity_hash(config_path1)
    sig1 = _sign_approval(privkey, "sec-team", "REPLAY-1", cfg_hash1)
    config1["governance"]["approval"]["config_sha256"] = cfg_hash1
    config1["governance"]["approval"]["signature"] = sig1
    _write_yaml(config_path1, config1)

    policy_path = tmp_path / "policy.yaml"
    _write_yaml(policy_path, {"mode": "enforce"})

    # Evaluate config 1 (this should consume REPLAY-1)
    allowed, findings = evaluate_policy_governance(
        config1,
        config_path1,
        policy_path,
        db_path=db_file,
        public_key_b64=pubkey_b64,
        require_signature=True,
        require_baseline=False,
    )
    assert allowed is True

    # 2. Attempt to reuse REPLAY-1 for config 2 (which has a different hash)
    config2 = _base_config()
    config2["security_policies"]["security_mode"] = "lenient"
    config2["security_policies"]["leak_prevention_strategy"] = "log_only" # different setting -> different hash
    config_path2 = tmp_path / "config2.yaml"
    config2["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "REPLAY-1",
        "config_sha256": "",
        "signature": "",
    }
    _write_yaml(config_path2, config2)

    cfg_hash2 = compute_config_integrity_hash(config_path2)
    sig2 = _sign_approval(privkey, "sec-team", "REPLAY-1", cfg_hash2)
    config2["governance"]["approval"]["config_sha256"] = cfg_hash2
    config2["governance"]["approval"]["signature"] = sig2
    _write_yaml(config_path2, config2)

    # Evaluate config 2 - should detect reuse of REPLAY-1
    allowed, findings = evaluate_policy_governance(
        config2,
        config_path2,
        policy_path,
        db_path=db_file,
        public_key_b64=pubkey_b64,
        require_signature=True,
        require_baseline=False,
    )
    assert allowed is False
    assert any(f.code == "ticket_replay_detected" for f in findings)


def test_governance_rejects_expired_ticket_match(tmp_path: Path):
    privkey, pubkey_b64 = _generate_ed25519_keypair()
    db_file = tmp_path / "tickets.db"

    # Pre-populate registry with an expired ticket
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS consumed_tickets (
            ticket_id TEXT PRIMARY KEY,
            config_hash TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
        """
    )
    # Ticket from 95 days ago (expired)
    expired_time = time.time() - (95 * 86400)
    cursor.execute(
        "INSERT INTO consumed_tickets (ticket_id, config_hash, timestamp) VALUES (?, ?, ?)",
        ("EXPIRED-TICKET", "0" * 64, expired_time)
    )
    conn.commit()
    conn.close()

    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient"
    config_path = tmp_path / "config.yaml"
    config["governance"]["approval"] = {
        "status": "approved",
        "approver": "sec-team",
        "ticket": "EXPIRED-TICKET",
        "config_sha256": "",
        "signature": "",
    }
    _write_yaml(config_path, config)

    cfg_hash = compute_config_integrity_hash(config_path)
    sig = _sign_approval(privkey, "sec-team", "EXPIRED-TICKET", cfg_hash)

    config["governance"]["approval"]["config_sha256"] = cfg_hash
    config["governance"]["approval"]["signature"] = sig
    _write_yaml(config_path, config)

    # Pre-populate DB to match this exact hash so it's a hash match, but expired
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute("UPDATE consumed_tickets SET config_hash = ? WHERE ticket_id = ?", (cfg_hash, "EXPIRED-TICKET"))
    conn.commit()
    conn.close()

    policy_path = tmp_path / "policy.yaml"
    _write_yaml(policy_path, {"mode": "enforce"})

    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        db_path=db_file,
        public_key_b64=pubkey_b64,
        require_signature=True,
        ticket_ttl_seconds=90 * 86400,
        require_baseline=False,
    )
    assert allowed is False
    assert any(f.code == "ticket_expired" for f in findings)


def test_governance_rejects_missing_baseline_under_enforcement(tmp_path: Path):
    config = _base_config()
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "enforce"})

    # enforcement requires baseline
    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        baseline_config_path=None,
        require_signature=False,
    )
    assert allowed is False
    assert any(f.code == "baseline_missing" for f in findings)


def test_governance_rejects_missing_baseline_version(tmp_path: Path):
    config = _base_config()
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "enforce"})

    baseline_path = tmp_path / "baseline.yaml"
    # missing version key
    _write_yaml(baseline_path, {"security_policies": {"security_mode": "balanced"}})

    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        baseline_config_path=baseline_path,
        require_signature=False,
    )
    assert allowed is False
    assert any(f.code == "baseline_version_missing" for f in findings)


def test_governance_cumulative_drift_against_baseline(tmp_path: Path):
    config = _base_config()
    config["security_policies"]["security_mode"] = "lenient" # drift!
    config_path = tmp_path / "config.yaml"
    policy_path = tmp_path / "policy.yaml"
    _write_yaml(config_path, config)
    _write_yaml(policy_path, {"mode": "enforce"})

    baseline_path = tmp_path / "baseline.yaml"
    _write_yaml(baseline_path, {
        "version": 1,
        "security_policies": {"security_mode": "balanced"}
    })

    # No approval block -> should fail due to drift
    allowed, findings = evaluate_policy_governance(
        config,
        config_path,
        policy_path,
        baseline_config_path=baseline_path,
        require_signature=False,
    )
    assert allowed is False
    assert any(f.code == "approval_required" for f in findings)

