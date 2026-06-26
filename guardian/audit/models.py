"""
Data models for the GuardianAI Audit module.

Defines the core data structures for audit scans, attack vectors,
findings, and scoring results.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AttackCategory(str, Enum):
    """OWASP LLM Top 10 + GuardianAI-specific categories."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT = "LLM02"
    LLM03_SUPPLY_CHAIN = "LLM03"
    LLM04_DATA_POISONING = "LLM04"
    LLM05_OUTPUT_HANDLING = "LLM05"
    LLM06_SENSITIVE_DISCLOSURE = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07"
    LLM08_EMBEDDING_WEAKNESS = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10"
    JAILBREAK = "JAILBREAK"
    ENCODING_BYPASS = "ENCODING"
    COMPLIANCE = "COMPLIANCE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    """Result of a single attack vector execution."""
    BLOCKED = "BLOCKED"       # Target correctly refused the attack
    PASSED = "PASSED"         # Target complied with the attack (vulnerability!)
    PARTIAL = "PARTIAL"       # Target partially complied — ambiguous
    ERROR = "ERROR"           # Network/auth error during test
    SKIPPED = "SKIPPED"       # Vector skipped (e.g., rate limited)


class ScanMode(str, Enum):
    QUICK = "quick"           # Top ~50 critical vectors
    STANDARD = "standard"     # ~120 vectors across all categories
    FULL = "full"             # 200+ vectors, all categories, encoding variants


class Grade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    A_MINUS = "A-"
    B_PLUS = "B+"
    B = "B"
    B_MINUS = "B-"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class AttackVector:
    """A single attack test case."""
    id: str
    name: str
    category: AttackCategory
    severity: Severity
    prompt: str
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    description: str = ""
    owasp_ref: str = ""
    tags: List[str] = field(default_factory=list)
    mode_tier: ScanMode = ScanMode.STANDARD  # minimum scan mode to include this


@dataclass
class Finding:
    """Result of executing one attack vector against the target."""
    vector_id: str
    vector_name: str
    category: AttackCategory
    severity: Severity
    status: FindingStatus
    request_prompt: str
    response_text: str
    response_time_ms: float
    confidence: float = 0.0          # 0.0-1.0 confidence in the classification
    evidence_notes: str = ""
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class CategoryScore:
    """Score for a single OWASP/audit category."""
    category: AttackCategory
    total_vectors: int
    blocked: int
    passed: int
    partial: int
    errors: int
    score_pct: float       # 0-100
    weight: float          # category weight in final score
    weighted_score: float  # score_pct * weight
    critical_findings: List[Finding] = field(default_factory=list)


@dataclass
class AuditScore:
    """Final aggregated audit score."""
    overall_score: float    # 0-100
    grade: Grade
    category_scores: List[CategoryScore] = field(default_factory=list)
    total_vectors: int = 0
    total_blocked: int = 0
    total_passed: int = 0
    total_partial: int = 0
    total_errors: int = 0


@dataclass
class TargetConfig:
    """Configuration for the AI endpoint being audited."""
    endpoint_url: str
    api_key: str = ""
    model: str = ""
    auth_type: str = "bearer"       # bearer, api-key-header, basic, none
    auth_header: str = "Authorization"
    request_template: Optional[Dict[str, Any]] = None
    max_tokens: int = 512
    temperature: float = 0.0        # deterministic for reproducible scans
    timeout_sec: float = 30.0
    rate_limit_rps: float = 2.0     # requests per second cap


@dataclass
class AuditScan:
    """Top-level audit scan record."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: Optional[TargetConfig] = None
    mode: ScanMode = ScanMode.STANDARD
    categories: List[AttackCategory] = field(default_factory=lambda: list(AttackCategory))
    findings: List[Finding] = field(default_factory=list)
    score: Optional[AuditScore] = None
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    status: str = "pending"  # pending, running, completed, failed
    error_message: str = ""

    @property
    def duration_sec(self) -> Optional[float]:
        if self.completed_at and self.started_at:
            return round(self.completed_at - self.started_at, 2)
        return None
