"""Static secret and IaC misconfiguration scanning helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
from typing import Iterable


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".venv",
    ".venv312",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    "artifacts",
    "htmlcov",
    "models",
    ".cache",
}

DEFAULT_EXCLUDE_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".mp4",
    ".zip",
    ".whl",
    ".pyc",
    # Binary executables — produce false-positive regex matches
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".dat",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pdb",
    ".incomplete",
    ".part",
    ".tmp",
    ".bin",
}

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "openai_api_key": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=+/]*"),
    "generic_secret_assign": re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?[^\s'\"#]{6,}"
    ),
}

IAC_SUSPICIOUS_PATTERNS: dict[str, re.Pattern[str]] = {
    "hardcoded_secret_env": re.compile(
        r"(?i)(?:environment|env)\b[\s\S]{0,300}\b(?:password|secret|api[_-]?key|token)\b[^\\n]{0,200}[:=]\s*['\"]?[^\s'\"#]{6,}"
    ),
    "terraform_secret_literal": re.compile(
        r'(?i)\b(?:password|secret|api[_-]?key|token)\b\s*=\s*"[^"]{6,}"'
    ),
    "iac_secret_kv_line": re.compile(
        r'(?i)\b(?:password|secret|api[_-]?key|token)\b\s*[:=]\s*["\']?[A-Za-z0-9_\-./+=]{8,}'
    ),
}

IAC_FILE_SUFFIXES = {".tf", ".tfvars", ".yaml", ".yml", ".json"}
IAC_FILE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "Dockerfile", "dockerfile"}


@dataclass
class ScanFinding:
    file_path: str
    rule: str
    line: int
    preview: str
    scanner: str


def _iter_files(root: Path) -> Iterable[Path]:
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS]
        dp = Path(dirpath)
        for name in filenames:
            path = dp / name
            if path.suffix.lower() in DEFAULT_EXCLUDE_SUFFIXES:
                continue
            try:
                if path.stat().st_size > 10 * 1024 * 1024:
                    continue
            except OSError:
                pass
            yield path


def _load_allowlist(allowlist_path: Path | None) -> list[str]:
    if not allowlist_path or not allowlist_path.exists():
        return []
    lines: list[str] = []
    for line in allowlist_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _is_allowlisted(path: str, preview: str, allowlist_entries: list[str]) -> bool:
    target = f"{path}:{preview}"
    return any(entry in target for entry in allowlist_entries)


def _scan_patterns(
    root: Path,
    patterns: dict[str, re.Pattern[str]],
    scanner_name: str,
    allowlist_entries: list[str],
    iac_only: bool = False,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    for file_path in _iter_files(root):
        if iac_only:
            lower_name = file_path.name.lower()
            if file_path.suffix.lower() not in IAC_FILE_SUFFIXES and lower_name not in {
                name.lower() for name in IAC_FILE_NAMES
            }:
                continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            for rule, pattern in patterns.items():
                if not pattern.search(line):
                    continue
                preview = line.strip()[:180]
                normalized = str(file_path).replace("\\", "/")
                if _is_allowlisted(normalized, preview, allowlist_entries):
                    continue
                findings.append(
                    ScanFinding(
                        file_path=normalized,
                        rule=rule,
                        line=idx,
                        preview=preview,
                        scanner=scanner_name,
                    )
                )
    return findings


def run_secret_scan(project_root: Path, allowlist_path: Path | None = None) -> list[ScanFinding]:
    allowlist_entries = _load_allowlist(allowlist_path)
    return _scan_patterns(project_root, SECRET_PATTERNS, "sast_secret_scan", allowlist_entries)


def run_iac_scan(project_root: Path, allowlist_path: Path | None = None) -> list[ScanFinding]:
    allowlist_entries = _load_allowlist(allowlist_path)
    return _scan_patterns(project_root, IAC_SUSPICIOUS_PATTERNS, "iac_scan", allowlist_entries, iac_only=True)


def run_git_history_scan(
    project_root: Path,
    allowlist_path: Path | None = None,
    max_commits: int = 200,
) -> list[ScanFinding]:
    """Scan git commit diffs for leaked secrets in historical commits."""
    allowlist_entries = _load_allowlist(allowlist_path)
    root = Path(project_root)

    inside = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        check=False,
    )
    if inside.returncode != 0 or "true" not in inside.stdout.lower():
        return []

    proc = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "log",
            "--all",
            f"-n{max_commits}",
            "-p",
            "--no-color",
            '--pretty=format:__COMMIT__%H',
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    )
    if proc.returncode != 0:
        return []

    findings: list[ScanFinding] = []
    current_file = "<unknown>"
    for idx, line in enumerate(proc.stdout.splitlines(), start=1):
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        preview = content.strip()[:180]
        normalized = current_file.replace("\\", "/")
        for rule, pattern in SECRET_PATTERNS.items():
            if not pattern.search(content):
                continue
            if _is_allowlisted(normalized, preview, allowlist_entries):
                continue
            findings.append(
                ScanFinding(
                    file_path=normalized,
                    rule=rule,
                    line=idx,
                    preview=preview,
                    scanner="git_history_scan",
                )
            )
    return findings
