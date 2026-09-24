"""
Filesystem Sandbox — OS-Level File Access Control for AI Agents
================================================================
Feature #9: Restricts file system operations to an explicit allowlist
of directories/paths. Prevents AI agents from reading sensitive system
files, writing to critical directories, or escaping their sandbox.

Key Capabilities:
    1. Path allowlist — only allow access to explicitly permitted dirs
    2. Path denylist — block access to sensitive system paths
    3. Read/Write/Execute permission model per path
    4. Path traversal prevention — normalize and block ../../../etc/passwd
    5. Symlink attack prevention — resolve symlinks before checking
    6. Glob pattern support — allow "*.py" but deny "*.exe"
    7. Temporary file sandbox — auto-create sandboxed tmp dirs
    8. Audit logging — log all access attempts (allowed + denied)
    9. Runtime hot-add/remove rules
   10. Stats & export

Author: GuardianAI Team
License: MIT
"""
import fnmatch
import logging
import os
import re
import stat
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("guardian_fs_sandbox")


# ─── Default deny paths ─────────────────────────────────────────────────────

DEFAULT_DENIED_PATHS_UNIX = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh",
    "/root",
    "/proc/kcore",
    "/dev/mem",
    "/dev/kmem",
    "/boot",
    "/var/log/auth.log",
    "/var/log/secure",
    "/home/*/.ssh",
    "/home/*/.gnupg",
    "/home/*/.bash_history",
]

DEFAULT_DENIED_PATHS_WINDOWS = [
    "C:\\Windows\\System32\\config",
    "C:\\Windows\\System32\\drivers",
    "C:\\Users\\*\\AppData\\Local\\Microsoft\\Credentials",
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials",
    "C:\\Users\\*\\.ssh",
    "C:\\Users\\*\\.gnupg",
    "C:\\ProgramData\\Microsoft\\Crypto",
    "C:\\Windows\\repair",
    "C:\\Windows\\debug",
    "C:\\pagefile.sys",
    "C:\\hiberfil.sys",
]

DEFAULT_DENIED_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".com",
    ".scr", ".pif", ".msi", ".ps1", ".vbs", ".wsf",
    ".hta", ".cpl", ".inf", ".reg",
]


class Permission:
    """File access permission flags."""
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 4
    READ_WRITE = READ | WRITE
    ALL = READ | WRITE | EXECUTE


class SandboxRule:
    """A single sandbox rule: path pattern + permission."""
    def __init__(self, path: str, permission: int = Permission.NONE,
                 action: str = "allow"):
        self.path = os.path.normpath(path).replace("\\", "/")
        self.permission = permission
        self.action = action  # "allow" or "deny"

    def matches(self, target: str) -> bool:
        target_norm = target.replace("\\", "/")
        # Exact match
        if target_norm == self.path:
            return True
        # Directory prefix match
        if target_norm.startswith(self.path + "/"):
            return True
        # Glob match
        if fnmatch.fnmatch(target_norm, self.path):
            return True
        return False

    def __repr__(self):
        return f"SandboxRule({self.path!r}, perm={self.permission}, action={self.action})"


class FilesystemSandbox:
    """
    Enforces file access control for AI agent operations.
    Uses an explicit allowlist + denylist model with path traversal prevention.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        fs_cfg = config.get("filesystem_sandbox", {})

        # ── Rules ────────────────────────────────────────────────────
        self.allow_rules: List[SandboxRule] = []
        self.deny_rules: List[SandboxRule] = []

        # Load allow rules from config
        for entry in fs_cfg.get("allowed_paths", []):
            if isinstance(entry, str):
                self.allow_rules.append(SandboxRule(entry, Permission.READ_WRITE, "allow"))
            elif isinstance(entry, dict):
                perm = self._parse_permission(entry.get("permission", "read"))
                self.allow_rules.append(SandboxRule(entry["path"], perm, "allow"))

        # Load deny rules from config + defaults
        for path in fs_cfg.get("denied_paths", []):
            self.deny_rules.append(SandboxRule(path, Permission.NONE, "deny"))

        # Add platform defaults if not disabled
        if fs_cfg.get("use_default_denylists", True):
            defaults = DEFAULT_DENIED_PATHS_WINDOWS if os.name == "nt" else DEFAULT_DENIED_PATHS_UNIX
            for path in defaults:
                self.deny_rules.append(SandboxRule(path, Permission.NONE, "deny"))

        # ── Extension blocking ───────────────────────────────────────
        self.denied_extensions: Set[str] = set(
            fs_cfg.get("denied_extensions", DEFAULT_DENIED_EXTENSIONS)
        )

        # ── Symlink policy ───────────────────────────────────────────
        self.resolve_symlinks: bool = fs_cfg.get("resolve_symlinks", True)

        # ── Sandbox temp dir ─────────────────────────────────────────
        self.sandbox_tmp: Optional[str] = fs_cfg.get("sandbox_tmp_dir", None)
        if self.sandbox_tmp:
            os.makedirs(self.sandbox_tmp, exist_ok=True)

        # ── Stats ────────────────────────────────────────────────────
        self._stats = {
            "total_checks": 0,
            "allowed": 0,
            "denied": 0,
            "denied_traversal": 0,
            "denied_extension": 0,
            "denied_symlink": 0,
            "denied_by_rule": 0,
        }
        self._audit_log: List[Dict[str, Any]] = []

        logger.info(
            f"FilesystemSandbox initialized: {len(self.allow_rules)} allow rules, "
            f"{len(self.deny_rules)} deny rules, "
            f"{len(self.denied_extensions)} blocked extensions."
        )

    # ─── Permission parsing ──────────────────────────────────────────────

    @staticmethod
    def _parse_permission(perm_str: str) -> int:
        perm_str = perm_str.lower()
        if perm_str in ("all", "rwx"):
            return Permission.ALL
        if perm_str in ("rw", "read_write", "readwrite"):
            return Permission.READ_WRITE
        if perm_str in ("r", "read", "readonly"):
            return Permission.READ
        if perm_str in ("w", "write", "writeonly"):
            return Permission.WRITE
        if perm_str in ("x", "execute", "exec"):
            return Permission.EXECUTE
        return Permission.READ

    # ─── Core: Access Check ──────────────────────────────────────────────

    def check_access(self, path: str, operation: str = "read") -> Tuple[bool, str]:
        """
        Check if an operation is allowed on a path.
        
        Args:
            path: The file/directory path to check.
            operation: "read", "write", or "execute".
            
        Returns:
            (allowed: bool, reason: str)
        """
        self._stats["total_checks"] += 1
        required_perm = {"read": Permission.READ, "write": Permission.WRITE,
                         "execute": Permission.EXECUTE}.get(operation, Permission.READ)

        # 1. Normalize path — prevent traversal attacks
        try:
            normalized = self._normalize_path(path)
        except ValueError as e:
            self._stats["denied_traversal"] += 1
            self._stats["denied"] += 1
            self._log_access(path, operation, False, f"traversal_attack: {e}")
            return False, f"path_traversal_blocked: {e}"

        # 2. Symlink resolution
        if self.resolve_symlinks and os.path.exists(normalized):
            try:
                resolved = os.path.realpath(normalized)
                if resolved != normalized:
                    # Path changed after symlink resolution — recheck
                    normalized_check = self._safe_normpath(resolved)
                    if normalized_check != self._safe_normpath(normalized):
                        self._stats["denied_symlink"] += 1
                        self._stats["denied"] += 1
                        self._log_access(path, operation, False,
                                         f"symlink_escape: {normalized} -> {resolved}")
                        return False, f"symlink_escape_blocked: {normalized} -> {resolved}"
                    normalized = resolved
            except OSError:
                pass

        # 3. Extension check (for write/execute)
        if operation in ("write", "execute"):
            ext = os.path.splitext(normalized)[1].lower()
            if ext in self.denied_extensions:
                self._stats["denied_extension"] += 1
                self._stats["denied"] += 1
                self._log_access(path, operation, False, f"blocked_extension: {ext}")
                return False, f"blocked_extension: {ext}"

        # 4. Deny rules (checked first — deny takes precedence)
        for rule in self.deny_rules:
            if rule.matches(normalized):
                self._stats["denied_by_rule"] += 1
                self._stats["denied"] += 1
                self._log_access(path, operation, False, f"deny_rule: {rule.path}")
                return False, f"denied_by_rule: {rule.path}"

        # 5. Allow rules
        for rule in self.allow_rules:
            if rule.matches(normalized) and (rule.permission & required_perm):
                self._stats["allowed"] += 1
                self._log_access(path, operation, True, f"allow_rule: {rule.path}")
                return True, f"allowed_by_rule: {rule.path}"

        # 6. Default: if no allow rules configured, allow (open sandbox)
        #    If allow rules exist but none matched, deny (closed sandbox)
        if self.allow_rules:
            self._stats["denied"] += 1
            self._log_access(path, operation, False, "no_matching_allow_rule")
            return False, "no_matching_allow_rule"
        else:
            # Open sandbox mode — no allowlist means everything allowed
            self._stats["allowed"] += 1
            self._log_access(path, operation, True, "open_sandbox")
            return True, "open_sandbox"

    def is_read_allowed(self, path: str) -> bool:
        """Convenience: check if reading a path is allowed."""
        return self.check_access(path, "read")[0]

    def is_write_allowed(self, path: str) -> bool:
        """Convenience: check if writing to a path is allowed."""
        return self.check_access(path, "write")[0]

    # ─── Path Normalization (traversal prevention) ───────────────────────

    def _normalize_path(self, path: str) -> str:
        """
        Normalize a path, blocking traversal attempts.
        Raises ValueError if path contains traversal sequences.
        """
        if not path:
            raise ValueError("empty path")

        # Iteratively unquote URL-encoded paths up to fixed point (handles single, double, multi-level encoding)
        curr = path
        for _ in range(10):
            if "\x00" in curr:
                raise ValueError("null byte in path")

            raw = curr.replace("\\", "/")
            # Path traversal segments: ../ or /.. or /../ or .. or ...
            if re.search(r"(?:^|/)\.{2,}(?:/|$)", raw):
                raise ValueError(f"path contains traversal sequences: {path}")

            nxt = urllib.parse.unquote(curr)
            if nxt == curr:
                break
            curr = nxt

        normalized = os.path.normpath(os.path.abspath(path))
        if "\x00" in normalized:
            raise ValueError("null byte in normalized path")
        return normalized

    @staticmethod
    def _safe_normpath(path: str) -> str:
        return os.path.normpath(os.path.abspath(path)).replace("\\", "/").lower()

    # ─── Runtime Management ──────────────────────────────────────────────

    def add_allow_rule(self, path: str, permission: str = "read") -> bool:
        """Add an allow rule at runtime."""
        perm = self._parse_permission(permission)
        self.allow_rules.append(SandboxRule(path, perm, "allow"))
        logger.info(f"Added allow rule: {path} ({permission})")
        return True

    def add_deny_rule(self, path: str) -> bool:
        """Add a deny rule at runtime."""
        self.deny_rules.append(SandboxRule(path, Permission.NONE, "deny"))
        logger.info(f"Added deny rule: {path}")
        return True

    def remove_allow_rule(self, path: str) -> bool:
        """Remove an allow rule by path."""
        norm = os.path.normpath(path).replace("\\", "/")
        before = len(self.allow_rules)
        self.allow_rules = [r for r in self.allow_rules if r.path != norm]
        return len(self.allow_rules) < before

    def remove_deny_rule(self, path: str) -> bool:
        """Remove a deny rule by path."""
        norm = os.path.normpath(path).replace("\\", "/")
        before = len(self.deny_rules)
        self.deny_rules = [r for r in self.deny_rules if r.path != norm]
        return len(self.deny_rules) < before

    # ─── Audit Log ───────────────────────────────────────────────────────

    def _log_access(self, path: str, operation: str, allowed: bool, reason: str):
        entry = {
            "path": path,
            "operation": operation,
            "allowed": allowed,
            "reason": reason,
            "timestamp": time.time(),
        }
        self._audit_log.append(entry)
        # Keep only last 500 entries
        if len(self._audit_log) > 500:
            self._audit_log = self._audit_log[-500:]

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent audit log entries."""
        return self._audit_log[-limit:]

    # ─── Stats & Export ──────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return sandbox statistics."""
        return {
            **self._stats,
            "allow_rules_count": len(self.allow_rules),
            "deny_rules_count": len(self.deny_rules),
            "denied_extensions_count": len(self.denied_extensions),
            "resolve_symlinks": self.resolve_symlinks,
            "sandbox_tmp": self.sandbox_tmp,
        }

    def export_rules(self) -> Dict[str, Any]:
        """Export all rules as serializable dict."""
        return {
            "allow_rules": [{"path": r.path, "permission": r.permission, "action": r.action}
                            for r in self.allow_rules],
            "deny_rules": [{"path": r.path, "action": r.action}
                           for r in self.deny_rules],
            "denied_extensions": sorted(self.denied_extensions),
        }

    def get_sandbox_tmp(self) -> str:
        """
        Get or create a sandboxed temporary directory.
        Safe for AI agents to write temp files to.
        """
        if self.sandbox_tmp:
            os.makedirs(self.sandbox_tmp, exist_ok=True)
            return self.sandbox_tmp
        # Auto-create one
        self.sandbox_tmp = tempfile.mkdtemp(prefix="guardian_sandbox_")
        # Add it to allow rules
        self.allow_rules.append(SandboxRule(self.sandbox_tmp, Permission.READ_WRITE, "allow"))
        logger.info(f"Created sandbox tmp dir: {self.sandbox_tmp}")
        return self.sandbox_tmp
