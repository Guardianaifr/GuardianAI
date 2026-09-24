"""
Isolated Code Execution Sandbox (OWASP ASI05)

Provides a hardened subprocess-based sandbox for executing untrusted code
with configurable CPU time limits, memory limits, network restrictions,
and timeout enforcement.

Security layers:
  1. Static pre-flight AST analysis blocking dangerous imports/calls
  2. Subprocess isolation (separate process, no shared memory)
  3. OS-level resource limits via `resource` module (Unix) or timeout-only (Windows)
  4. Configurable timeout with SIGKILL escalation
  5. Restricted builtins (no eval/exec/compile/__import__)
"""

from __future__ import annotations

import ast
import os
import platform
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class SandboxViolation(Exception):
    """Raised when sandbox policy is violated."""


class ExecutionStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    POLICY_VIOLATION = "policy_violation"
    RESOURCE_EXCEEDED = "resource_exceeded"


@dataclass
class ExecutionResult:
    """Result of a sandboxed code execution."""
    status: ExecutionStatus
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: float = 0.0
    memory_used_bytes: int = 0
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "memory_used_bytes": self.memory_used_bytes,
            "violations": self.violations,
        }


# ── Static Analysis ──────────────────────────────────────────────────────────

# Imports that are never allowed inside the sandbox
BLOCKED_IMPORTS: Set[str] = {
    # System & Execution
    "os", "sys", "subprocess", "shutil", "socket", "ctypes",
    "signal", "multiprocessing", "threading", "_thread", "importlib",
    "code", "codeop", "compileall", "py_compile",
    "platform", "pathlib", "inspect", "gc", "io", "tempfile",
    "posix", "nt", "genericpath", "posixpath", "ntpath",
    "linecache", "traceback", "runpy", "zipimport", "pkgutil",
    "types", "typing_extensions", "_posixsubprocess",
    # Network & Serialization & Filesystem
    "webbrowser", "http", "urllib", "requests", "httpx",
    "ftplib", "smtplib", "telnetlib", "xmlrpc", "selectors", "asyncio", "_asyncio",
    "pickle", "shelve", "marshal", "sqlite3", "zipfile", "tarfile",
    # Debuggers, Profilers, Disassemblers & Code Exec
    "pdb", "bdb", "dis", "trace", "timeit", "profile", "cProfile", "doctest", "pydoc", "unittest",
}

# Built-in names that are blocked
BLOCKED_BUILTINS: Set[str] = {
    "eval", "exec", "compile", "globals", "locals",
    "getattr", "setattr", "delattr", "vars", "dir",
    "open", "input", "breakpoint", "exit", "quit",
    "help", "memoryview",
}

# Dangerous attribute names that allow class-hierarchy and frame escapes
BLOCKED_ATTRIBUTES: Set[str] = {
    "__class__", "__dict__", "__getattribute__", "__getattr__", "__setattr__", "__delattr__", "__init_subclass__",
    "__subclasses__", "__bases__", "__base__", "__mro__",
    "__globals__", "__builtins__", "__code__", "__reduce__", "__reduce_ex__",
    "__closure__", "__func__", "__self__", "__wrapped__", "__loader__", "__spec__",
    "f_back", "f_globals", "f_builtins", "f_locals", "f_code",
    "gi_frame", "cr_frame", "ag_frame",
    "tb_frame", "tb_next",
}

# AST node types that indicate dangerous operations
BLOCKED_AST_NODES = (ast.AsyncFunctionDef,)  # async not needed in sandbox


def _static_analyze(code: str) -> List[str]:
    """Pre-flight static analysis of code for policy violations."""
    violations: List[str] = []

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        violations.append(f"Syntax error: {exc}")
        return violations

    for node in ast.walk(tree):
        # Block dangerous imports
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names: List[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in BLOCKED_IMPORTS:
                    violations.append(
                        f"Blocked import: '{name}' (line {node.lineno})"
                    )

        # Block dangerous attribute access
        if isinstance(node, ast.Attribute) and node.attr in BLOCKED_ATTRIBUTES:
            violations.append(
                f"Blocked attribute access: '.{node.attr}' (line {node.lineno})"
            )

        # Block direct access to __builtins__ or __import__ names
        if isinstance(node, ast.Name) and node.id in ("__builtins__", "__import__"):
            violations.append(
                f"Blocked access to '{node.id}' (line {node.lineno})"
            )

        # Block dangerous built-in calls and direct __import__
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                if func.id == "__import__":
                    violations.append(
                        f"Blocked direct __import__() call (line {node.lineno})"
                    )
                elif func.id in BLOCKED_BUILTINS:
                    violations.append(
                        f"Blocked builtin call: '{func.id}()' (line {node.lineno})"
                    )
            elif isinstance(func, ast.Attribute) and func.attr in ("system", "popen", "exec", "spawn", "fork"):
                violations.append(
                    f"Blocked method call: '.{func.attr}()' (line {node.lineno})"
                )

    return violations


# ── Sandbox Wrapper Script ───────────────────────────────────────────────────

_SANDBOX_WRAPPER = textwrap.dedent('''\
    import sys, json, resource as _res, traceback

    # Apply resource limits (Unix only)
    _mem_bytes = int(sys.argv[1])
    _cpu_secs  = int(sys.argv[2])

    if _mem_bytes > 0:
        _res.setrlimit(_res.RLIMIT_AS, (_mem_bytes, _mem_bytes))
    if _cpu_secs > 0:
        _res.setrlimit(_res.RLIMIT_CPU, (_cpu_secs, _cpu_secs))

    # Strip dangerous builtins and install guarded import
    _bi = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    _blocked = {BLOCKED_SET}
    _safe_builtins = {k: v for k, v in _bi.items() if k not in _blocked}
    _blocked_imports = {BLOCKED_IMPORTS_SET}
    _orig_import = _bi.get("__import__")

    def _safe_import(name, *args, _orig=_orig_import, _blocked_set=_blocked_imports, **kwargs):
        root = name.split(".")[0]
        if root in _blocked_set:
            raise ImportError(f"Prohibited import '{name}' in sandbox")
        return _orig(name, *args, **kwargs)

    _safe_builtins["__import__"] = _safe_import
    _globals = {"__builtins__": _safe_builtins}

    # Scrub sys.modules of dangerous modules
    for _mod in list(sys.modules.keys()):
        _root = _mod.split(".")[0]
        if _root in _blocked_imports:
            sys.modules.pop(_mod, None)

    _code = sys.stdin.read()
    del _bi, _blocked, _blocked_imports, _orig_import

    try:
        exec(compile(_code, "<sandbox>", "exec"), _globals)
    except MemoryError:
        print("SANDBOX_RESOURCE_EXCEEDED: memory limit", file=sys.stderr)
        sys.exit(137)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
''')

_SANDBOX_WRAPPER_WIN = textwrap.dedent('''\
    import sys, json, traceback

    # Strip dangerous builtins and install guarded import
    _bi = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__
    _blocked = {BLOCKED_SET}
    _safe_builtins = {k: v for k, v in _bi.items() if k not in _blocked}
    _blocked_imports = {BLOCKED_IMPORTS_SET}
    _orig_import = _bi.get("__import__")

    def _safe_import(name, *args, _orig=_orig_import, _blocked_set=_blocked_imports, **kwargs):
        root = name.split(".")[0]
        if root in _blocked_set:
            raise ImportError(f"Prohibited import '{name}' in sandbox")
        return _orig(name, *args, **kwargs)

    _safe_builtins["__import__"] = _safe_import
    _globals = {"__builtins__": _safe_builtins}

    # Scrub sys.modules of dangerous modules
    for _mod in list(sys.modules.keys()):
        _root = _mod.split(".")[0]
        if _root in _blocked_imports:
            sys.modules.pop(_mod, None)

    _code = sys.stdin.read()
    del _bi, _blocked, _blocked_imports, _orig_import

    try:
        exec(compile(_code, "<sandbox>", "exec"), _globals)
    except MemoryError:
        print("SANDBOX_RESOURCE_EXCEEDED: memory limit", file=sys.stderr)
        sys.exit(137)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
''')


# ── ExecutionSandbox ─────────────────────────────────────────────────────────

@dataclass
class SandboxConfig:
    """Configuration for the execution sandbox."""
    timeout_seconds: int = 30
    memory_limit_mb: int = 256
    cpu_limit_seconds: int = 10
    max_output_bytes: int = 1_048_576  # 1 MB
    allow_network: bool = False
    blocked_imports: Set[str] = field(default_factory=lambda: set(BLOCKED_IMPORTS))
    blocked_builtins: Set[str] = field(default_factory=lambda: set(BLOCKED_BUILTINS))


class ExecutionSandbox:
    """
    Hardened subprocess-based sandbox for running untrusted Python code.

    Features:
      - Static AST pre-flight analysis
      - Subprocess isolation with resource limits
      - Configurable CPU, memory, and wall-clock time limits
      - Restricted builtins environment
      - Platform-aware: resource limits on Unix, timeout-only on Windows
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._is_unix = platform.system() != "Windows"

    def execute(self, code: str) -> ExecutionResult:
        """Execute untrusted code in an isolated subprocess."""
        # Phase 1: Static analysis
        violations = _static_analyze(code)
        if violations:
            return ExecutionResult(
                status=ExecutionStatus.POLICY_VIOLATION,
                violations=violations,
            )

        # Phase 2: Subprocess execution
        return self._run_in_subprocess(code)

    def _run_in_subprocess(self, code: str) -> ExecutionResult:
        """Run code in an isolated subprocess with resource limits."""
        blocked_set_repr = repr(self.config.blocked_builtins)
        blocked_imports_repr = repr(self.config.blocked_imports)

        if self._is_unix:
            wrapper = _SANDBOX_WRAPPER.replace(
                "{BLOCKED_SET}", blocked_set_repr
            ).replace("{BLOCKED_IMPORTS_SET}", blocked_imports_repr)
        else:
            wrapper = _SANDBOX_WRAPPER_WIN.replace(
                "{BLOCKED_SET}", blocked_set_repr
            ).replace("{BLOCKED_IMPORTS_SET}", blocked_imports_repr)

        # Write wrapper to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="sandbox_"
        ) as tmp:
            tmp.write(wrapper)
            wrapper_path = tmp.name

        try:
            mem_bytes = self.config.memory_limit_mb * 1024 * 1024
            cpu_secs = self.config.cpu_limit_seconds

            cmd = [sys.executable, wrapper_path]
            if self._is_unix:
                cmd.extend([str(mem_bytes), str(cpu_secs)])

            env = os.environ.copy()
            # Restrict PATH to prevent shell escapes
            env["PATH"] = ""

            start = time.monotonic()

            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=tempfile.gettempdir(),
            )

            try:
                stdout_bytes, stderr_bytes = proc.communicate(
                    input=code.encode("utf-8"),
                    timeout=self.config.timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                elapsed = (time.monotonic() - start) * 1000
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    stderr=f"Execution timed out after {self.config.timeout_seconds}s",
                    duration_ms=elapsed,
                )

            elapsed = (time.monotonic() - start) * 1000
            stdout_str = stdout_bytes.decode("utf-8", errors="replace")[
                : self.config.max_output_bytes
            ]
            stderr_str = stderr_bytes.decode("utf-8", errors="replace")[
                : self.config.max_output_bytes
            ]

            # Detect resource limit violations
            if proc.returncode == 137 or "SANDBOX_RESOURCE_EXCEEDED" in stderr_str:
                return ExecutionResult(
                    status=ExecutionStatus.RESOURCE_EXCEEDED,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    exit_code=proc.returncode,
                    duration_ms=elapsed,
                    violations=["Resource limit exceeded"],
                )

            if proc.returncode != 0:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    exit_code=proc.returncode,
                    duration_ms=elapsed,
                )

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                stdout=stdout_str,
                stderr=stderr_str,
                exit_code=0,
                duration_ms=elapsed,
            )
        finally:
            try:
                os.unlink(wrapper_path)
            except OSError:
                pass
