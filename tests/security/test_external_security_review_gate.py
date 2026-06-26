import json
import subprocess
import sys


def test_external_security_review_gate_passes_with_recent_report(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "review_date": "2026-03-01",
                "open_critical_findings": 0,
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [
            sys.executable,
            "tools/check_external_security_review.py",
            "--report",
            str(report),
            "--max-age-days",
            "365",
            "--max-open-critical",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout.strip())
    assert payload["status"] == "ok"
