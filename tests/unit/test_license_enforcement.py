from __future__ import annotations

from pathlib import Path

import guardianctl


def test_issue_license_binds_to_machine_prefix():
    machine = "a" * 64
    key = guardianctl.issue_license_key(machine)
    assert key.startswith("GAI-aaaaaaaaaaaa-")


def test_activate_license_rejects_different_machine(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(guardianctl, "LICENSE_ACTIVATION_PATH", tmp_path / "license_activation.json")
    monkeypatch.setattr(guardianctl, "get_machine_fingerprint", lambda: "b" * 64)
    ok, msg = guardianctl.activate_license("GAI-aaaaaaaaaaaa-ABCDEFGHIJKL")
    assert ok is False
    assert "different machine" in msg.lower()


def test_activate_and_check_license_success(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(guardianctl, "LICENSE_ACTIVATION_PATH", tmp_path / "license_activation.json")
    monkeypatch.setattr(guardianctl, "LICENSE_ENFORCEMENT", True)
    machine_id = "c" * 64
    monkeypatch.setattr(guardianctl, "get_machine_fingerprint", lambda: machine_id)
    key = "GAI-cccccccccccc-ABCDEFGHIJKL"
    ok, _ = guardianctl.activate_license(key)
    assert ok is True
    ready, _ = guardianctl.check_license_ready()
    assert ready is True


def test_env_license_key_overrides_stale_activation(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(guardianctl, "LICENSE_ACTIVATION_PATH", tmp_path / "license_activation.json")
    monkeypatch.setattr(guardianctl, "LICENSE_ENFORCEMENT", True)
    stale = tmp_path / "license_activation.json"
    stale.write_text(
        "license_key: GAI-aaaaaaaaaaaa-ABCDEFGHIJKL\nmachine_id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        encoding="utf-8",
    )
    machine_id = "c" * 64
    monkeypatch.setattr(guardianctl, "get_machine_fingerprint", lambda: machine_id)
    monkeypatch.setenv("GUARDIAN_LICENSE_KEY", "GAI-cccccccccccc-ABCDEFGHIJKL")

    ready, message = guardianctl.check_license_ready()

    assert ready is True
    assert "GUARDIAN_LICENSE_KEY" in message


def test_issue_license_blocked_when_issuer_secret_not_set(monkeypatch):
    monkeypatch.setattr(guardianctl, "LICENSE_ISSUER_SECRET", "")
    ok, msg = guardianctl.can_issue_license("anything")
    assert ok is False
    assert "disabled" in msg.lower()


def test_issue_license_requires_matching_issuer_secret(monkeypatch):
    monkeypatch.setattr(guardianctl, "LICENSE_ISSUER_SECRET", "topsecret")
    ok_bad, msg_bad = guardianctl.can_issue_license("wrong")
    assert ok_bad is False
    assert "invalid issuer secret" in msg_bad.lower()

    ok_good, _ = guardianctl.can_issue_license("topsecret")
    assert ok_good is True
