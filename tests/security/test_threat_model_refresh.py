import subprocess
import sys

from tools.run_threat_model_refresh import current_quarter


def test_current_quarter_mapping():
    assert current_quarter(1704067200) == "2024-Q1"  # 2024-01-01 UTC
    assert current_quarter(1719792000) == "2024-Q3"  # 2024-07-01 UTC


def test_threat_model_refresh_tool(tmp_path):
    out = tmp_path / "threat_model_quarterly.md"
    proc = subprocess.run(
        [
            sys.executable,
            "tools/run_threat_model_refresh.py",
            "--output",
            str(out),
            "--owner",
            "secops",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    text = out.read_text(encoding="utf-8")
    assert "OWASP LLM Review" in text
    assert "MITRE ATLAS Mapping" in text
