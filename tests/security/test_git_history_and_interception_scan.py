from __future__ import annotations

from pathlib import Path
import json
import shutil
import subprocess

import pytest

from security.interception_scan import scan_har_for_leaks, scan_har_directory
from security.static_scan import run_git_history_scan


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_git_history_scan_detects_historical_secret(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)

    leaked = repo / "config.py"
    leaked.write_text("OPENAI_API_KEY='sk-abc123def456ghi789jkl012mno345pqr'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "add leaked secret"], cwd=repo, check=True)

    leaked.write_text("OPENAI_API_KEY='redacted'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "remove leaked secret"], cwd=repo, check=True)

    findings = run_git_history_scan(repo, max_commits=20)
    assert findings
    assert any(f.rule == "openai_api_key" for f in findings)
    assert any(f.scanner == "git_history_scan" for f in findings)


def test_har_interception_scan_detects_response_leak(tmp_path: Path):
    har = {
        "log": {
            "entries": [
                {
                    "request": {"url": "http://localhost/v1/chat/completions"},
                    "response": {
                        "content": {
                            "text": '{"choices":[{"message":{"content":"token sk-abc123def456ghi789jkl012mno345pqr"}}]}'
                        }
                    },
                }
            ]
        }
    }
    har_path = tmp_path / "capture.har"
    har_path.write_text(json.dumps(har), encoding="utf-8")

    findings = scan_har_for_leaks(har_path)
    assert findings
    assert findings[0].scanner == "har_interception_scan"
    assert findings[0].location == "response.body"


def test_har_interception_scan_allows_benign_traffic(tmp_path: Path):
    har = {
        "log": {
            "entries": [
                {
                    "request": {"url": "http://localhost/v1/chat/completions"},
                    "response": {
                        "content": {"text": '{"choices":[{"message":{"content":"hello world"}}]}'}
                    },
                }
            ]
        }
    }
    har_path = tmp_path / "capture.har"
    har_path.write_text(json.dumps(har), encoding="utf-8")

    findings = scan_har_for_leaks(har_path)
    assert findings == []


def test_har_directory_scan_supports_burp_or_zap_exports(tmp_path: Path):
    intercept_dir = tmp_path / "artifacts" / "intercepts"
    intercept_dir.mkdir(parents=True)
    har = {
        "log": {
            "entries": [
                {
                    "request": {"url": "http://localhost/v1/completions"},
                    "response": {
                        "content": {
                            "text": '{"choices":[{"message":{"content":"AWS key AKIA1234567890ABCDEF"}}]}'
                        }
                    },
                }
            ]
        }
    }
    (intercept_dir / "zap_capture.har").write_text(json.dumps(har), encoding="utf-8")

    findings = scan_har_directory(intercept_dir)
    assert findings
    assert findings[0].source.endswith("/v1/completions")
