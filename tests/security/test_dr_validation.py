from pathlib import Path
import subprocess
import sys

from guardian.utils.backup import backup_db, latest_backup, restore_db, drill_backup_restore


def test_backup_and_restore_roundtrip(tmp_path):
    db = tmp_path / "guardian.db"
    db.write_bytes(b"sqlite-test")
    backup_dir = tmp_path / "backups"

    backup_path = backup_db(str(db), backup_dir=str(backup_dir), keep_last=3)
    assert Path(backup_path).exists()
    assert latest_backup(str(backup_dir)) is not None

    restored = tmp_path / "restored.db"
    restore_db(backup_path, str(restored))
    assert restored.exists()
    assert restored.read_bytes() == db.read_bytes()


def test_drill_reports_restore_ok(tmp_path):
    db = tmp_path / "guardian.db"
    db.write_bytes(b"sqlite-test")
    result = drill_backup_restore(str(db), backup_dir=str(tmp_path / "dr"))
    assert result["restore_ok"] is True
    assert result["elapsed_seconds"] >= 0


def test_run_dr_validation_tool(tmp_path):
    db = tmp_path / "guardian.db"
    db.write_bytes(b"sqlite-test")
    evidence = tmp_path / "dr_validation.md"
    proc = subprocess.run(
        [
            sys.executable,
            "tools/run_dr_validation.py",
            "--db-path",
            str(db),
            "--backup-dir",
            str(tmp_path / "dr"),
            "--rto-target-seconds",
            "60",
            "--evidence-out",
            str(evidence),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert evidence.exists()
    text = evidence.read_text(encoding="utf-8")
    assert "RTO target met: `True`" in text
