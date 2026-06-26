from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guardian.utils.backup import drill_backup_restore


def main() -> int:
    parser = argparse.ArgumentParser(description="Run backup/restore DR drill and emit evidence.")
    parser.add_argument("--db-path", default="guardian.db")
    parser.add_argument("--backup-dir", default="artifacts/dr/backups")
    parser.add_argument("--rto-target-seconds", type=float, default=30.0)
    parser.add_argument("--evidence-out", default="artifacts/evidence/dr_validation.md")
    args = parser.parse_args()

    db_path = Path(args.db_path)
    if not db_path.exists():
        print(json.dumps({"status": "failed", "reason": "db_missing", "db_path": str(db_path)}))
        return 1

    result = drill_backup_restore(str(db_path), backup_dir=args.backup_dir)
    passed = bool(result["restore_ok"] and result["elapsed_seconds"] <= args.rto_target_seconds)

    evidence_path = Path(args.evidence_out)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    evidence_path.write_text(
        "\n".join(
            [
                "# DR Validation Report",
                "",
                f"Run timestamp: {now}",
                f"DB path: `{db_path}`",
                f"Backup path: `{result['backup_path']}`",
                f"Restore path: `{result['restore_path']}`",
                f"Elapsed seconds (RTO drill): `{result['elapsed_seconds']}`",
                f"RTO target seconds: `{args.rto_target_seconds}`",
                f"Restore integrity: `{result['restore_ok']}`",
                f"RTO target met: `{passed}`",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "status": "ok" if passed else "failed",
                "result": result,
                "rto_target_seconds": args.rto_target_seconds,
                "evidence_out": str(evidence_path),
            }
        )
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
