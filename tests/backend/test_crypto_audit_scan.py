from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as backend_main
from guardian.audit.crypto_scanner import ScanResult


class _SuccessfulScanner:
    def __init__(self, target_url: str, target_name: str | None = None, depth=None):
        self.target_url = target_url
        self.target_name = target_name or "Demo Target"
        self.depth = depth

    def run_scan(self, progress_callback=None):
        if progress_callback:
            progress_callback(0, 0, "Discovered 1 candidate endpoints", "discovered")
            progress_callback(1, 2, "Direct System Override", "protected")
            progress_callback(2, 2, "System Prompt Extraction", "protected")
        return ScanResult(
            target_url=self.target_url,
            target_name=self.target_name,
            scan_id="SCAN-TEST-001",
            scan_depth="standard",
            started_at="2026-05-17T00:00:00+00:00",
            completed_at="2026-05-17T00:00:02+00:00",
            duration_seconds=2.0,
            total_vectors=2,
            vulnerabilities_found=0,
            protected_count=2,
            score=92.5,
            grade="A",
            findings=[
                {
                    "vector_id": "PI_001",
                    "vector_name": "Direct System Override",
                    "pillar": "Prompt Injection & Jailbreak",
                    "severity": "critical",
                    "status": "protected",
                },
                {
                    "vector_id": "DE_001",
                    "vector_name": "System Prompt Extraction",
                    "pillar": "Data Exfiltration & Privacy",
                    "severity": "high",
                    "status": "protected",
                },
            ],
            pillar_scores={
                "Prompt Injection & Jailbreak": {"total": 1, "vulnerable": 0, "protected": 1, "score": 100.0},
                "Data Exfiltration & Privacy": {"total": 1, "vulnerable": 0, "protected": 1, "score": 100.0},
            },
        )


class _FailingScanner:
    def __init__(self, *args, **kwargs):
        pass

    def run_scan(self, progress_callback=None):
        raise RuntimeError("upstream target unavailable")


class _ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)


def test_crypto_scan_generates_report_and_badge_artifacts(tmp_path, monkeypatch):
    import sys
    backend_main = sys.modules["backend.main"]
    audit_dir = tmp_path / "audit"
    ar = sys.modules["backend.routers.audit_routes"]
    sr = sys.modules["backend.routers.scan_routes"]
    monkeypatch.setattr(backend_main, "AUDIT_ARTIFACTS_DIR", audit_dir)
    monkeypatch.setattr(ar, "AUDIT_ARTIFACTS_DIR", audit_dir)
    monkeypatch.setattr(sr, "AUDIT_ARTIFACTS_DIR", audit_dir)
    monkeypatch.setattr(backend_main, "PUBLIC_BASE_URL", "https://guardian.example")
    monkeypatch.setenv("GUARDIAN_BADGE_SECRET_KEY", "unit-test-secret")
    monkeypatch.setattr("guardian.audit.crypto_scanner.CryptoAuditScanner", _SuccessfulScanner)

    client = TestClient(backend_main.app)
    response = client.post(
        "/api/v1/scan",
        json={
            "target_url": "https://demo.example/v1/chat/completions",
            "target_name": "Monad Demo",
            "depth": "standard",
        },
        auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "SCAN-TEST-001"
    assert body["grade"] == "A"
    assert body["artifacts"]["report_url"] == "https://guardian.example/api/v1/scan/SCAN-TEST-001/report"
    assert body["artifacts"]["badge_svg_url"] == "https://guardian.example/api/v1/audits/SCAN-TEST-001/svg"
    assert body["badge"]["payload"]["report_id"] == "SCAN-TEST-001"

    report_path = audit_dir / "report_SCAN-TEST-001.html"
    badge_json_path = audit_dir / "badge_SCAN-TEST-001.json"
    badge_svg_path = audit_dir / "badge_SCAN-TEST-001.svg"
    scan_json_files = list(audit_dir.glob("scan_SCAN-TEST-001_*.json"))

    assert report_path.exists()
    assert badge_json_path.exists()
    assert badge_svg_path.exists()
    assert len(scan_json_files) == 1

    report_response = client.get("/api/v1/scan/SCAN-TEST-001/report", auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS))
    assert report_response.status_code == 200
    assert "GuardianAI Security Audit Report" in report_response.text
    assert "Monad Demo" in report_response.text

    audits_response = client.get("/api/v1/audits", auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS))
    assert audits_response.status_code == 200
    audits = audits_response.json()["audits"]
    assert len(audits) == 1
    assert audits[0]["id"] == "SCAN-TEST-001"
    assert audits[0]["grade"] == "A"

    svg_response = client.get(
        "/api/v1/audits/SCAN-TEST-001/svg",
        auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS)
    )
    assert svg_response.status_code == 200
    assert "<svg" in svg_response.text

    verify_response = client.post(
        "/api/v1/verify-badge",
        json={"badge_data": body["badge"]},
        auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS)
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["status"] == "valid"


def test_crypto_scan_returns_http_500_on_scanner_failure(monkeypatch):
    import sys
    backend_main = sys.modules["backend.main"]
    monkeypatch.setattr("guardian.audit.crypto_scanner.CryptoAuditScanner", _FailingScanner)

    client = TestClient(backend_main.app)
    response = client.post(
        "/api/v1/scan",
        json={"target_url": "https://demo.example/v1/chat/completions", "depth": "quick"},
        auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS),
    )

    assert response.status_code == 500
    assert response.json()["error"] == "Internal scan error"


def test_crypto_scan_job_reports_live_status_and_result(tmp_path, monkeypatch):
    import sys
    backend_main = sys.modules["backend.main"]
    audit_dir = tmp_path / "audit"
    ar = sys.modules["backend.routers.audit_routes"]
    sr = sys.modules["backend.routers.scan_routes"]
    monkeypatch.setattr(backend_main, "AUDIT_ARTIFACTS_DIR", audit_dir)
    monkeypatch.setattr(ar, "AUDIT_ARTIFACTS_DIR", audit_dir)
    monkeypatch.setattr(sr, "AUDIT_ARTIFACTS_DIR", audit_dir)
    monkeypatch.setattr(backend_main, "PUBLIC_BASE_URL", "https://guardian.example")
    monkeypatch.setenv("GUARDIAN_BADGE_SECRET_KEY", "unit-test-secret")
    monkeypatch.setattr("guardian.audit.crypto_scanner.CryptoAuditScanner", _SuccessfulScanner)
    monkeypatch.setattr(backend_main.threading, "Thread", _ImmediateThread)

    client = TestClient(backend_main.app)
    create_response = client.post(
        "/api/v1/scan-jobs",
        json={
            "target_url": "https://demo.example",
            "target_name": "Monad Demo",
            "depth": "standard",
        },
        auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS),
    )

    assert create_response.status_code == 200
    job = create_response.json()
    assert job["status"] == "completed"
    assert job["progress_pct"] == 100.0
    assert job["result"]["scan_id"] == "SCAN-TEST-001"
    assert len(job["logs"]) >= 4

    detail_response = client.get(f"/api/v1/scan-jobs/{job['job_id']}", auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS))
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["status"] == "completed"
    assert detail["result"]["grade"] == "A"

    list_response = client.get("/api/v1/scan-jobs", auth=(backend_main.ADMIN_USER, backend_main.ADMIN_PASS))
    assert list_response.status_code == 200
    jobs = list_response.json()["jobs"]
    assert len(jobs) >= 1
    assert jobs[0]["job_id"] == job["job_id"]
    assert jobs[0]["result"]["scan_id"] == "SCAN-TEST-001"
