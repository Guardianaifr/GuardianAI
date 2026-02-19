"""Daily SQLite Backup Utility."""
import shutil, os
from datetime import datetime
from pathlib import Path

def backup_db(db_path, backup_dir="backups"):
    Path(backup_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(backup_dir, f"guardian_{ts}.db")
    shutil.copy2(db_path, dest)
    # Keep only last 7 backups
    backups = sorted(Path(backup_dir).glob("guardian_*.db"))
    for old in backups[:-7]:
        old.unlink()
    return dest

if __name__ == "__main__":
    for db in ["guardian.db", "backend/guardian.db"]:
        if os.path.exists(db):
            print(f"Backed up: {backup_db(db)}")