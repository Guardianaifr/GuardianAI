"""
Deep Binary Model Scanner (Pre-Deployment Model Scanning)

Scans serialized ML model files for deserialization exploits and
embedded code-execution payloads:

  - .pkl / .pickle: Pickle opcode analysis detecting REDUCE, GLOBAL,
    INST, BUILD, STACK_GLOBAL, OBJ (arbitrary code execution vectors)
  - .pt / .pth: PyTorch model files (pickle-inside-zip analysis)
  - .safetensors: Header JSON injection / metadata abuse detection
  - .onnx: Custom operator and external data reference scanning
  - .gguf: GGUF v2/v3 metadata key validation for malicious payloads

Each scan returns a structured report with finding severity, opcode
details, and pass/fail verdict.
"""

from __future__ import annotations

import io
import json
import os
import pickle
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Set, Tuple


class FindingSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanFinding:
    """A single finding from a model file scan."""
    severity: FindingSeverity
    category: str
    description: str
    offset: Optional[int] = None
    opcode: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
        }
        if self.offset is not None:
            d["offset"] = self.offset
        if self.opcode:
            d["opcode"] = self.opcode
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class ScanReport:
    """Report from scanning a model file."""
    file_path: str
    file_type: str
    file_size: int
    is_safe: bool
    findings: List[ScanFinding] = field(default_factory=list)
    summary: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "is_safe": self.is_safe,
            "critical_findings": self.critical_count,
            "high_findings": self.high_count,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
        }


# ── Pickle Opcode Analysis ───────────────────────────────────────────────────

# Dangerous pickle opcodes that enable arbitrary code execution
# Reference: https://docs.python.org/3/library/pickletools.html
DANGEROUS_OPCODES: Dict[int, str] = {
    0x52: "REDUCE",        # Apply callable to args (code execution)
    0x63: "GLOBAL",        # Push a global object (import + getattr)
    0x69: "INST",          # Build instance (legacy, calls __init__)
    0x62: "BUILD",         # Apply __setstate__ or __dict__.update
    0x93: "STACK_GLOBAL",  # Same as GLOBAL but from stack args
    0x81: "NEWOBJ",        # Build object using cls.__new__
    0x92: "NEWOBJ_EX",     # Extended NEWOBJ with kwargs
}

# Known dangerous module.callable patterns in pickle GLOBAL/STACK_GLOBAL
DANGEROUS_CALLABLES: Set[str] = {
    "os.system", "os.popen", "os.execve", "os.execvp",
    "subprocess.call", "subprocess.Popen", "subprocess.run",
    "subprocess.check_output", "subprocess.check_call",
    "builtins.eval", "builtins.exec", "builtins.compile",
    "builtins.__import__", "builtins.getattr",
    "nt.system", "posix.system",
    "webbrowser.open",
    "shutil.rmtree", "shutil.move",
    "ctypes.cdll", "ctypes.windll",
    "code.InteractiveConsole",
    "pickle.loads",
    "marshal.loads",
    "importlib.import_module",
}


def _scan_pickle_bytes(data: bytes, source_label: str = "") -> List[ScanFinding]:
    """Scan raw pickle bytes for dangerous opcodes."""
    findings: List[ScanFinding] = []
    i = 0
    length = len(data)

    while i < length:
        op = data[i]

        if op in DANGEROUS_OPCODES:
            opcode_name = DANGEROUS_OPCODES[op]
            findings.append(ScanFinding(
                severity=FindingSeverity.CRITICAL,
                category="pickle_dangerous_opcode",
                description=(
                    f"Dangerous pickle opcode {opcode_name} (0x{op:02x}) "
                    f"detected at offset {i}{' in ' + source_label if source_label else ''}. "
                    f"This opcode enables arbitrary code execution during deserialization."
                ),
                offset=i,
                opcode=opcode_name,
            ))

        # Check for GLOBAL opcode content (module.callable string)
        if op == 0x63:  # GLOBAL
            # Read the module\ncallable string
            end = data.find(b"\n", i + 1)
            if end != -1:
                end2 = data.find(b"\n", end + 1)
                if end2 != -1:
                    module = data[i + 1:end].decode("ascii", errors="replace")
                    name = data[end + 1:end2].decode("ascii", errors="replace")
                    full_name = f"{module}.{name}"
                    if full_name in DANGEROUS_CALLABLES:
                        findings.append(ScanFinding(
                            severity=FindingSeverity.CRITICAL,
                            category="pickle_dangerous_callable",
                            description=(
                                f"Pickle GLOBAL references dangerous callable "
                                f"'{full_name}' at offset {i}. "
                                f"This will execute code during deserialization."
                            ),
                            offset=i,
                            opcode="GLOBAL",
                            metadata={"callable": full_name},
                        ))

        i += 1

    return findings


# ── File Type Scanners ───────────────────────────────────────────────────────

def _scan_pickle_file(file_path: str, data: bytes) -> ScanReport:
    """Scan a .pkl/.pickle file."""
    findings = _scan_pickle_bytes(data, source_label=os.path.basename(file_path))
    is_safe = all(f.severity != FindingSeverity.CRITICAL for f in findings)
    return ScanReport(
        file_path=file_path,
        file_type="pickle",
        file_size=len(data),
        is_safe=is_safe,
        findings=findings,
        summary=f"{'SAFE' if is_safe else 'UNSAFE'}: {len(findings)} finding(s) in pickle file",
    )


def _scan_pytorch_file(file_path: str, data: bytes) -> ScanReport:
    """Scan a .pt/.pth PyTorch file (zip containing pickle data.pkl)."""
    findings: List[ScanFinding] = []

    # PyTorch saves models as ZIP archives with pickle inside
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.endswith(".pkl") or name.endswith("data.pkl") or "pickle" in name.lower():
                    pkl_data = zf.read(name)
                    inner_findings = _scan_pickle_bytes(pkl_data, source_label=name)
                    findings.extend(inner_findings)

            # Check for unexpected file types inside the archive
            for name in zf.namelist():
                if name.endswith((".py", ".sh", ".bat", ".exe", ".dll", ".so")):
                    findings.append(ScanFinding(
                        severity=FindingSeverity.HIGH,
                        category="pytorch_suspicious_archive_entry",
                        description=(
                            f"PyTorch archive contains suspicious file: '{name}'. "
                            f"Legitimate model files should not contain executables or scripts."
                        ),
                        metadata={"archive_entry": name},
                    ))
    except (zipfile.BadZipFile, Exception):
        # If not a valid ZIP, try scanning as raw pickle
        findings = _scan_pickle_bytes(data, source_label=os.path.basename(file_path))

    is_safe = all(f.severity != FindingSeverity.CRITICAL for f in findings)
    return ScanReport(
        file_path=file_path,
        file_type="pytorch",
        file_size=len(data),
        is_safe=is_safe,
        findings=findings,
        summary=f"{'SAFE' if is_safe else 'UNSAFE'}: {len(findings)} finding(s) in PyTorch file",
    )


def _scan_safetensors_file(file_path: str, data: bytes) -> ScanReport:
    """
    Scan a .safetensors file.

    Safetensors format: [8-byte LE header_size][JSON header][tensor data]
    We validate the JSON header for injection attacks.
    """
    findings: List[ScanFinding] = []

    if len(data) < 8:
        findings.append(ScanFinding(
            severity=FindingSeverity.HIGH,
            category="safetensors_invalid",
            description="File too small to be a valid safetensors file.",
        ))
        return ScanReport(
            file_path=file_path, file_type="safetensors",
            file_size=len(data), is_safe=False, findings=findings,
            summary="UNSAFE: Invalid safetensors file",
        )

    # Parse header size (8-byte little-endian)
    header_size = struct.unpack("<Q", data[:8])[0]

    # Sanity check: header shouldn't be larger than the file
    if header_size > len(data) - 8:
        findings.append(ScanFinding(
            severity=FindingSeverity.HIGH,
            category="safetensors_header_overflow",
            description=(
                f"Header size ({header_size}) exceeds remaining file size "
                f"({len(data) - 8}). Possible corruption or attack."
            ),
        ))
        return ScanReport(
            file_path=file_path, file_type="safetensors",
            file_size=len(data), is_safe=False, findings=findings,
            summary="UNSAFE: Header size overflow",
        )

    # Excessive header size (potential DoS or metadata injection)
    if header_size > 10_000_000:  # 10 MB header is suspicious
        findings.append(ScanFinding(
            severity=FindingSeverity.HIGH,
            category="safetensors_excessive_header",
            description=(
                f"Abnormally large header ({header_size} bytes). "
                f"May indicate metadata injection attack."
            ),
        ))

    # Parse and validate JSON header
    try:
        header_json = data[8:8 + header_size].decode("utf-8")
        header = json.loads(header_json)

        # Check for suspicious metadata keys
        suspicious_keys = {"__exec__", "__import__", "__code__", "eval", "exec", "system"}
        for key in header:
            key_lower = key.lower()
            if key_lower in suspicious_keys:
                findings.append(ScanFinding(
                    severity=FindingSeverity.CRITICAL,
                    category="safetensors_metadata_injection",
                    description=(
                        f"Suspicious metadata key '{key}' in safetensors header. "
                        f"May indicate code injection attempt."
                    ),
                    metadata={"key": key},
                ))

            # Check tensor metadata for anomalies
            if isinstance(header[key], dict):
                if "data_offsets" in header[key]:
                    offsets = header[key]["data_offsets"]
                    if isinstance(offsets, list) and len(offsets) == 2:
                        start, end = offsets
                        if end < start:
                            findings.append(ScanFinding(
                                severity=FindingSeverity.WARNING,
                                category="safetensors_invalid_offset",
                                description=f"Tensor '{key}' has invalid data offsets [{start}, {end}].",
                            ))

    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        findings.append(ScanFinding(
            severity=FindingSeverity.HIGH,
            category="safetensors_header_parse_error",
            description=f"Failed to parse safetensors header: {exc}",
        ))

    is_safe = all(f.severity not in (FindingSeverity.CRITICAL, FindingSeverity.HIGH) for f in findings)
    return ScanReport(
        file_path=file_path, file_type="safetensors",
        file_size=len(data), is_safe=is_safe, findings=findings,
        summary=f"{'SAFE' if is_safe else 'UNSAFE'}: {len(findings)} finding(s) in safetensors file",
    )


def _scan_onnx_file(file_path: str, data: bytes) -> ScanReport:
    """
    Scan an .onnx file for custom operator exploits and external data references.

    ONNX files are Protocol Buffer serialized. We scan for suspicious patterns
    without requiring the full onnx library.
    """
    findings: List[ScanFinding] = []

    # Check for external data references (path traversal)
    suspicious_patterns = [
        (b"external_data", "external_data_reference",
         "ONNX model references external data files which could load malicious payloads."),
        (b"custom_ops", "custom_operator",
         "ONNX model uses custom operators which could contain malicious code."),
        (b"../", "path_traversal",
         "ONNX model contains path traversal pattern in external data reference."),
        (b"..\\", "path_traversal_win",
         "ONNX model contains Windows path traversal pattern."),
    ]

    for pattern, category, description in suspicious_patterns:
        idx = data.find(pattern)
        if idx != -1:
            findings.append(ScanFinding(
                severity=FindingSeverity.WARNING if "traversal" not in category else FindingSeverity.HIGH,
                category=f"onnx_{category}",
                description=description,
                offset=idx,
            ))

    # Check for embedded Python code
    python_markers = [b"exec(", b"eval(", b"__import__", b"subprocess", b"os.system"]
    for marker in python_markers:
        idx = data.find(marker)
        if idx != -1:
            findings.append(ScanFinding(
                severity=FindingSeverity.CRITICAL,
                category="onnx_embedded_code",
                description=(
                    f"ONNX model contains embedded code pattern "
                    f"'{marker.decode()}' at offset {idx}."
                ),
                offset=idx,
            ))

    is_safe = all(f.severity != FindingSeverity.CRITICAL for f in findings)
    return ScanReport(
        file_path=file_path, file_type="onnx",
        file_size=len(data), is_safe=is_safe, findings=findings,
        summary=f"{'SAFE' if is_safe else 'UNSAFE'}: {len(findings)} finding(s) in ONNX file",
    )


def _scan_gguf_file(file_path: str, data: bytes) -> ScanReport:
    """
    Scan a .gguf file for malicious metadata.

    GGUF format (v2/v3):
      - Magic: b'GGUF' (4 bytes)
      - Version: uint32 LE
      - Tensor count: uint64 LE (v3) or uint32 LE (v2)
      - Metadata KV count: uint64 LE (v3) or uint32 LE (v2)
      - Metadata key-value pairs
    """
    findings: List[ScanFinding] = []

    # Validate magic number
    if len(data) < 4 or data[:4] != b"GGUF":
        findings.append(ScanFinding(
            severity=FindingSeverity.HIGH,
            category="gguf_invalid_magic",
            description="File does not have valid GGUF magic number.",
        ))
        return ScanReport(
            file_path=file_path, file_type="gguf",
            file_size=len(data), is_safe=False, findings=findings,
            summary="UNSAFE: Invalid GGUF file",
        )

    if len(data) < 12:
        findings.append(ScanFinding(
            severity=FindingSeverity.HIGH,
            category="gguf_truncated",
            description="GGUF file too small to contain valid header.",
        ))
        return ScanReport(
            file_path=file_path, file_type="gguf",
            file_size=len(data), is_safe=False, findings=findings,
            summary="UNSAFE: Truncated GGUF file",
        )

    # Parse version
    version = struct.unpack("<I", data[4:8])[0]
    if version not in (2, 3):
        findings.append(ScanFinding(
            severity=FindingSeverity.WARNING,
            category="gguf_unknown_version",
            description=f"GGUF version {version} is not a recognized version (expected 2 or 3).",
            metadata={"version": version},
        ))

    # Scan for suspicious embedded content in metadata region
    # (first 1MB or entire file if smaller — metadata is at the front)
    scan_region = data[:min(len(data), 1_048_576)]

    suspicious_strings = [
        b"exec(", b"eval(", b"system(", b"__import__",
        b"subprocess", b"os.popen", b"<script",
    ]
    for marker in suspicious_strings:
        idx = scan_region.find(marker)
        if idx != -1:
            findings.append(ScanFinding(
                severity=FindingSeverity.CRITICAL,
                category="gguf_malicious_metadata",
                description=(
                    f"GGUF metadata contains suspicious pattern "
                    f"'{marker.decode(errors='replace')}' at offset {idx}."
                ),
                offset=idx,
            ))

    is_safe = all(f.severity != FindingSeverity.CRITICAL for f in findings)
    return ScanReport(
        file_path=file_path, file_type="gguf",
        file_size=len(data), is_safe=is_safe, findings=findings,
        summary=f"{'SAFE' if is_safe else 'UNSAFE'}: {len(findings)} finding(s) in GGUF file",
    )


# ── Main Scanner Class ───────────────────────────────────────────────────────

_EXTENSION_MAP = {
    ".pkl": _scan_pickle_file,
    ".pickle": _scan_pickle_file,
    ".pt": _scan_pytorch_file,
    ".pth": _scan_pytorch_file,
    ".safetensors": _scan_safetensors_file,
    ".onnx": _scan_onnx_file,
    ".gguf": _scan_gguf_file,
}


class DeepBinaryScanner:
    """
    Deep binary scanner for ML model files.

    Supports: .pkl, .pickle, .pt, .pth, .safetensors, .onnx, .gguf

    Usage:
        scanner = DeepBinaryScanner()
        report = scanner.scan_file("/path/to/model.pkl")
        if not report.is_safe:
            print(report.findings)
    """

    SUPPORTED_EXTENSIONS: Set[str] = set(_EXTENSION_MAP.keys())

    def __init__(self, *, max_file_size_mb: int = 4096):
        self.max_file_size = max_file_size_mb * 1024 * 1024

    def scan_file(self, file_path: str) -> ScanReport:
        """Scan a model file and return a structured report."""
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext not in _EXTENSION_MAP:
            return ScanReport(
                file_path=file_path,
                file_type="unknown",
                file_size=0,
                is_safe=False,
                findings=[ScanFinding(
                    severity=FindingSeverity.WARNING,
                    category="unsupported_format",
                    description=f"File extension '{ext}' is not supported. "
                                f"Supported: {sorted(self.SUPPORTED_EXTENSIONS)}",
                )],
                summary=f"SKIPPED: Unsupported file extension '{ext}'",
            )

        if not path.exists():
            return ScanReport(
                file_path=file_path,
                file_type=ext.lstrip("."),
                file_size=0,
                is_safe=False,
                findings=[ScanFinding(
                    severity=FindingSeverity.HIGH,
                    category="file_not_found",
                    description=f"File not found: {file_path}",
                )],
                summary="UNSAFE: File not found",
            )

        file_size = path.stat().st_size
        if file_size > self.max_file_size:
            return ScanReport(
                file_path=file_path,
                file_type=ext.lstrip("."),
                file_size=file_size,
                is_safe=False,
                findings=[ScanFinding(
                    severity=FindingSeverity.WARNING,
                    category="file_too_large",
                    description=(
                        f"File size ({file_size} bytes) exceeds maximum "
                        f"({self.max_file_size} bytes). Scan skipped."
                    ),
                )],
                summary="SKIPPED: File too large",
            )

        data = path.read_bytes()
        scanner_fn = _EXTENSION_MAP[ext]
        return scanner_fn(file_path, data)

    def scan_bytes(self, data: bytes, file_type: str) -> ScanReport:
        """Scan raw bytes with a specified file type."""
        ext = f".{file_type}" if not file_type.startswith(".") else file_type
        ext = ext.lower()

        if ext not in _EXTENSION_MAP:
            return ScanReport(
                file_path="<bytes>",
                file_type="unknown",
                file_size=len(data),
                is_safe=False,
                findings=[ScanFinding(
                    severity=FindingSeverity.WARNING,
                    category="unsupported_format",
                    description=f"File type '{ext}' is not supported.",
                )],
                summary=f"SKIPPED: Unsupported file type '{ext}'",
            )

        scanner_fn = _EXTENSION_MAP[ext]
        return scanner_fn("<bytes>", data)
