from pathlib import Path

from security.static_scan import run_secret_scan, run_iac_scan


def test_repo_scans_with_allowlist():
    root = Path(__file__).resolve().parents[2]
    allowlist = root / "guardian" / "config" / "secret_scan_allowlist.txt"

    secret_findings = run_secret_scan(root, allowlist)
    iac_findings = run_iac_scan(root, allowlist)

    assert secret_findings == []
    assert iac_findings == []
