import sqlite3
import subprocess
import sys


def test_data_governance_audit_tool(tmp_path):
    db = tmp_path / "guardian.db"
    conn = sqlite3.connect(str(db))
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE security_events (id INTEGER PRIMARY KEY, tenant_id TEXT, timestamp REAL)"
    )
    cur.execute("INSERT INTO security_events (tenant_id, timestamp) VALUES (?, ?)", ("tenant-1", 9999999999.0))
    conn.commit()
    conn.close()

    out = tmp_path / "data_governance_audit.md"
    proc = subprocess.run(
        [
            sys.executable,
            "tools/run_data_governance_audit.py",
            "--db-path",
            str(db),
            "--retention-days",
            "30",
            "--evidence-out",
            str(out),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    text = out.read_text(encoding="utf-8")
    assert "Retention policy pass: `True`" in text
