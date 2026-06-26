import subprocess
import sys


def test_incident_drill_tool(tmp_path):
    out = tmp_path / "incident_drill_report.md"
    proc = subprocess.run(
        [
            sys.executable,
            "tools/run_incident_drill.py",
            "--scenario",
            "injection",
            "--scenario",
            "auth_compromise",
            "--output",
            str(out),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    text = out.read_text(encoding="utf-8")
    assert "injection" in text
    assert "auth_compromise" in text
