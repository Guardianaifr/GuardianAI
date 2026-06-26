from pathlib import Path

from security.static_scan import run_secret_scan, run_iac_scan


def test_static_secret_scan_fixture(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    bad = proj / "app.py"
    bad.write_text("OPENAI_KEY='sk-abc123def456ghi789jkl012mno345pqr'\n", encoding="utf-8")

    findings = run_secret_scan(proj)
    assert findings
    assert any(f.rule == "openai_api_key" for f in findings)


def test_iac_scan_fixture(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    bad = proj / "docker-compose.yml"
    bad.write_text(
        "services:\n  app:\n    environment:\n      API_KEY: sk-abc123def456ghi789jkl012mno345pqr\n",
        encoding="utf-8",
    )
    findings = run_iac_scan(proj)
    assert findings
    assert findings[0].scanner == "iac_scan"
