"""SQLite backup and restore utility helpers."""
import os
import shutil
from datetime import datetime
from pathlib import Path
import time


def backup_db(db_path, backup_dir="backups", keep_last=7):
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(backup_dir, f"guardian_{ts}.db")
    shutil.copy2(db_path, dest)
    # Keep only last N backups
    backups = sorted(Path(backup_dir).glob("guardian_*.db"))
    for old in backups[:-int(keep_last)]:
        old.unlink()
    return dest


def latest_backup(backup_dir="backups"):
    backups = sorted(Path(backup_dir).glob("guardian_*.db"))
    if not backups:
        return None
    return str(backups[-1])


def restore_db(backup_path, db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_path, db_path)
    return db_path


def drill_backup_restore(db_path, backup_dir="backups"):
    start = time.perf_counter()
    backup_path = backup_db(db_path, backup_dir=backup_dir)
    restore_target = os.path.join(backup_dir, "drill_restore.db")
    restore_db(backup_path, restore_target)
    elapsed_s = time.perf_counter() - start
    ok = Path(restore_target).exists() and Path(restore_target).stat().st_size > 0
    return {
        "backup_path": backup_path,
        "restore_path": restore_target,
        "elapsed_seconds": round(elapsed_s, 3),
        "restore_ok": bool(ok),
    }


if __name__ == "__main__":
    for db in ["guardian.db", "backend/guardian.db"]:
        if os.path.exists(db):
            print(f"Backed up: {backup_db(db)}")
