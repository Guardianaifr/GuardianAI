import pytest
import sys
import os
import subprocess
import shutil
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from guardian.security.static_scan import run_git_history_scan, run_secret_scan

@pytest.fixture(scope="module")
def github_test_repo(tmp_path_factory):
    """
    Clones a real GitHub repository known to contain actual secrets and patterns
    for testing (truffleHogRegexes). This tests our scanners against real-world
    GitHub historical data.
    """
    repo_url = "https://github.com/dxa4481/truffleHogRegexes.git"
    clone_dir = tmp_path_factory.mktemp("github_data") / "truffleHogRegexes"
    
    # Clone the repository
    try:
        subprocess.run(
            ["git", "clone", repo_url, str(clone_dir)],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Failed to clone GitHub repository for testing. Network issue? Error: {e.stderr}")
    
    yield clone_dir

def test_real_github_history_scan(github_test_repo):
    """
    Tests the git_history_scan on a real GitHub repository's commit history.
    """
    findings = run_git_history_scan(github_test_repo, max_commits=500)
    
    # The truffleHogRegexes repo contains multiple historical commits adding/removing regexes
    # and sample secrets. Our scanner should find multiple leaks in the git history.
    assert len(findings) > 0, "Failed to find any secrets in real GitHub repository history!"
    
    # Verify we caught specific types of secrets (e.g., private keys, AWS keys, etc.)
    rule_types = {f.rule for f in findings}
    assert "private_key_block" in rule_types or "generic_secret_assign" in rule_types, \
        f"Did not find expected secret types. Found: {rule_types}"

def test_real_github_static_scan(github_test_repo):
    """
    Tests the static secret_scan on the current HEAD of a real GitHub repository.
    """
    findings = run_secret_scan(github_test_repo)
    
    assert len(findings) > 0, "Failed to find any secrets in real GitHub repository static files!"
    
    # The repo contains regexes.json with hardcoded examples.
    # Our generic_secret_assign or specific regexes should flag them.
    found_in_regexes_json = any("regexes.json" in f.file_path for f in findings)
    assert found_in_regexes_json, "Failed to find secrets in the expected regexes.json file from GitHub repo."

def test_real_github_data_structure(github_test_repo):
    """
    Validates that the findings contain the expected structure and line numbers 
    matching the real GitHub data.
    """
    findings = run_secret_scan(github_test_repo)
    
    for finding in findings:
        assert finding.line > 0
        assert finding.scanner == "sast_secret_scan"
        assert len(finding.preview) > 0
        assert "truffleHogRegexes" in finding.file_path or finding.file_path.startswith("regexes.json")
