from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_production_templates_exist():
    assert (ROOT / "deploy" / "production" / ".env.production.example").exists()
    assert (ROOT / "deploy" / "production" / "Caddyfile.example").exists()
    assert (ROOT / "deploy" / "production" / "guardianai.service.example").exists()
    assert (ROOT / "deploy" / "production" / "setup_production.ps1").exists()
    assert (ROOT / "deploy" / "production" / "verify_production.ps1").exists()


def test_runbook_exists():
    runbook = ROOT / "PRODUCTION_LAUNCH_RUNBOOK.md"
    assert runbook.exists()
    text = runbook.read_text(encoding="utf-8")
    assert "setup_production.ps1" in text
    assert "verify_production.ps1" in text
