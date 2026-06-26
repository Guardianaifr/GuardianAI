from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
import time


def main() -> int:
    parser = argparse.ArgumentParser(description="Run tenant retention/deletion governance audit.")
    parser.add_argument("--db-path", default="guardian.db")
    parser.add_argument("--retention-days", type=int, default=30)
    parser.add_argument("--evidence-out", default="artifacts/evidence/data_governance_audit.md")
    args = parser.parse_args()

    db_path = Path(args.db_path)
    if not db_path.exists():
        print(json.dumps({"status": "failed", "reason": "db_missing", "db_path": str(db_path)}))
        return 1

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cutoff = time.time() - (args.retention_days * 24 * 60 * 60)
    cur.execute("SELECT COUNT(*) FROM security_events WHERE timestamp < ?", (cutoff,))
    stale_count = int(cur.fetchone()[0])
    cur.execute("SELECT COUNT(DISTINCT tenant_id) FROM security_events")
    tenant_count = int(cur.fetchone()[0])
    conn.close()

    passed = stale_count == 0
    out = Path(args.evidence_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(
            [
                "# Data Governance Audit Report",
                "",
                f"Run timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                f"DB path: `{db_path}`",
                f"Retention policy (days): `{args.retention_days}`",
                f"Observed tenant count: `{tenant_count}`",
                f"Stale records older than retention: `{stale_count}`",
                f"Retention policy pass: `{passed}`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"status": "ok" if passed else "failed", "stale_records": stale_count, "output": str(out)}))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
