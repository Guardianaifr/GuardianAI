from __future__ import annotations

"""
MemoryPoisoningGuard v2 — Comprehensive memory-layer defense

Fixes from Independent Adversarial Security Audit:
1. Line 59 persistence bug: blocked poison no longer appended to serving memory
2. Input normalization: NFKC unicode, zero-width char strip, base64 decode scanning
3. Expanded pattern coverage: 30+ patterns covering paraphrases, indirect injection
4. Provenance tracking: source/author/trust_level per memory entry
5. Permission revocation: revoke by app_id, tombstone historical entries
6. Cross-agent isolation: agent-namespaced memory with explicit grant system
7. Quarantine audit log: separate from serving memory
"""

import base64
import re
import threading
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MemoryDecision:
    """Backward-compatible decision envelope."""
    action: str          # "allow" or "block"
    reason: str          # machine-readable reason code
    details: Dict[str, Any]
    severity: str = "HIGH"


@dataclass
class MemoryEntry:
    """A single memory record with full provenance metadata."""
    text: str
    timestamp: float
    source: str = "user"       # "user", "agent", "tool", "system"
    app_id: str = "default"
    agent_id: str = "default"
    trust_level: int = 100     # 0-100
    is_tombstoned: bool = False
    is_quarantined: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Input normalization constants
# ──────────────────────────────────────────────────────────────────────────────

INVISIBLE_CHARS = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u034f\u061c'
    r'\u115f\u1160\u17b4\u17b5\u180e'
    r'\u2000-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f'
    r'\ufff0-\ufff8]'
)
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
BASE64_SEGMENT = re.compile(r'[A-Za-z0-9+/]{20,}={0,3}')


# ──────────────────────────────────────────────────────────────────────────────
# Expanded adversarial pattern set (30+ patterns)
# ──────────────────────────────────────────────────────────────────────────────

_RAW_PATTERNS: list[str] = [
    # --- Instruction Override ---
    r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|directives|rules|guidelines|constraints|context)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above|earlier|preceding)?\s*(instructions|directives|rules|guidelines|constraints|safety|guardrails|context)",
    r"(?i)forget\s+(all|everything)\s+(previous\s+|prior\s+|above\s+|earlier\s+)?(instructions|directives|rules|context|you\s+know|you\s+were\s+told)",
    r"(?i)override\s+(all\s+)?(previous|prior|current|existing|safety|security)?\s*(instructions|directives|rules|settings|config)",
    # --- System directives ---
    r"(?i)system\s+(override|directive|command|instruction|prompt)",
    r"(?i)new\s+(instructions?|directives?|rules?|task|role|objective)",
    r"(?i)do\s+not\s+follow\s+(previous|prior|any|the)\s+(instructions|rules|directives|guidelines)",
    # --- Drain / Exfiltrate / Sweep ---
    r"(?i)(drain|sweep|exfiltrate|siphon|empty|liquidate)\s+(all\s+)?(the\s+)?(wallet|treasury|funds|balance|vault|assets|tokens|account)",
    r"(?i)(transfer|send|forward)\s+(all|every|entire|full|complete|remaining)\s+(eth|mon|token|fund|balance|asset|amount)",
    # --- Reveal Secrets ---
    r"(?i)(reveal|expose|show|display|output|print|leak|disclose|share)\s+(the\s+)?(private\s+key|seed\s+phrase|secret|password|mnemonic|api\s+key|credentials)",
    r"(?i)(give|tell|send)\s+me\s+(the\s+|your\s+)?(private\s+key|seed\s+phrase|secret|password|mnemonic)",
    # --- Bypass Safety ---
    r"(?i)(bypass|circumvent|disable|turn\s+off|deactivate|remove)\s+(the\s+)?(safety|security|guardrails?|guard|filter|restriction|protection|firewall|limit)",
    # --- Persist / Deferred Instructions ---
    r"(?i)(persist|store|save|remember|memorize|record)\s+(this|these|the\s+following)\s+(instruction|directive|rule|command|setting|override)",
    r"(?i)(always|from\s+now\s+on|henceforth|permanently|going\s+forward)\s+(do|execute|follow|obey|comply|perform|send|transfer|reveal)",
    r"(?i)(whenever|every\s+time|each\s+time|next\s+time|if\s+anyone\s+asks)\s+.{0,60}(send|transfer|forward|reveal|execute|sweep|drain)",
    r"(?i)(?:note\s+for\s+future\s+reference|memo|reminder\s+for\s+next\s+turn)[\s\S]{0,60}(?:must|execute|without\s+confirmation|slippage|tolerance)",
    r"(?i)(?:slippage\s+tolerance|slippage)\s+(?:is\s+now|set\s+to|change\s+to|=)?\s*(?:9[0-9]%|100%|unlimited)",
    r"(?i)(?:execute|transfer|send|trade)[\s\S]{0,40}without\s+(?:confirmation|verification|approval)",
    # --- Role Manipulation ---
    r"(?i)you\s+are\s+now\s+(a|an|the|my)?\s*(admin|administrator|root|superuser|unrestricted|unfiltered|jailbroken)",
    r"(?i)your\s+(new\s+)?(role|persona|identity|character|task|objective|mission)\s+(is|will\s+be|has\s+changed)",
    r"(?i)(act|behave|pretend|function)\s+(as|like)\s+(a|an|the)?\s*(admin|unrestricted|unfiltered|jailbroken|evil)",
    # --- Context Injection / Gaslighting (Princeton/Sentient vector) ---
    r"(?i)(user|admin|owner|developer)\s+(has\s+)?(said|agreed|confirmed|approved|authorized|instructed|updated|changed|set)\s+.{0,60}(address|wallet|recipient|destination|payout|target)",
    r"(?i)(you|we)\s+(previously\s+)?(agreed|confirmed|decided|established|set\s+up)\s+.{0,40}(address|wallet|recipient|payout|treasury)",
    r"(?i)(earlier|previously|before|in\s+discord|in\s+chat|last\s+time)\s+.{0,60}(agreed|confirmed|said|told|instructed)\s+.{0,40}(address|wallet|send|transfer|forward)",
    r"(?i)(designated|official|default|primary|new)\s+(treasury|payout|withdrawal|receiving)\s+(wallet|address)",
    # --- Delimiter / Context Boundary Injection ---
    r"(?i)\[(?:[A-Z_]*(?:SYSTEM|INTERNAL|ADMIN|ROOT|OVERRIDE|DIRECTIVE)[A-Z_]*)\]",
    r"(?i)---\s*\n?\s*\[?(?:SYSTEM|INTERNAL|ADMIN|OVERRIDE)",
    r"(?i)<\s*(?:system|admin|root|override|instruction)\s*>",
    # --- Prompt Injection Meta & Jailbreak ---
    r"(?i)(inject|insertion|injection|planted|implant)\s+(into\s+)?(memory|context|prompt|instruction|conversation)",
    r"(?i)jailbreak",
    r"(?i)(\bDAN\b|Do\s+Anything\s+Now)",
    r"(?i)\bthis\s+is\s+not\s+a\s+prompt\s+injection\b",
    r"(?i)======\s*END(\.|\s)",
    r"(?i)\battention\s*-\s*stop\b",
    r"(?i)\bas\s+a\s+language\s+model\s+free\b",
    r"(?i)\byou\s+are\s+supposed\s+to\s+answer\s+at\s+all\s+times\b",
    r"(?i)\b(that\s+was\s+ok\s+before|passed\s+the\s+first\s+test).{0,30}new\s+(challenge|task|test)\b",

    # --- System Prompt & Instruction Exfiltration ---
    r"(?i)\b(show|tell|print|output|display|give|repeat|leak|reveal|share|echo|return)\s+(me\s+)?(all\s+)?(the\s+|your\s+)?(initial|system|original|hidden|secret|internal|above|prior|underlying)\s+(prompt\s+texts?|instructions?|rules?|directives?|system\s+prompt|embeddings?)\b",
    r"(?i)\b(show|tell|reveal|print)\s+(me\s+)?(all\s+)?(your\s+prompt\s+texts?|the\s+system\s+prompt)\b",
    r"(?i)\b(print|spell-?\s*check\s+and\s+print)\s+.{0,30}above\s+prompt\b",
    r"(?i)\btell\s+me\s+what\s+your\s+(initial|original|system)\s+(instructions|prompt|rules)\s+(were|are)\b",
    r"(?i)\b(print|output)\s+(a\s+|an\s+)?improved\s+version\s+of\s+(it|the\s+text\s+above)\b",

    # --- Conversational Reset & Context Erasure ---
    r"(?i)\b(ignore|igmre)\s+(the\s+above|what\s+i\s+said\s+before|your\s+directions?|all\s+preceding\s+orders?|all\s+provided\s+context)\b",
    r"(?i)\bforget\s+(everything|all)\s+(before\s+that|so\s+far|we\s+discussed|i\s+have\s+told\s+you|waht['']?s\s+before)\b",
    r"(?i)\b(amnesia\s+and\s+forgot\s+everything|has\s+amnesia)\b",

    # --- Adversarial Roleplay & Persona Hijack ---
    r"(?i)\b(act|pretend|behave)\s+(as|like)\s+(a\s+|an\s+)?(unrestricted|jailbroken|evil|unfiltered|illegal|rogue|DAN)\b",
    r"(?i)\b(stay|remain)\s+in\s+(your|their)\s+roles?\s+without\s+.{0,30}(breaking|falling\s+out)\b",

    # --- Multilingual Injections (German & Spanish) ---
    r"(?i)\bvergiss\s+(jetzt\s+)?(alles|alle)\s*(,|.)?\s*(was|bisher|davor|zuvor|wir\s+bisher|ich\s+dir|bisherigen\s+auftr[äa]ge)\b",
    r"(?i)\b(drucken|zeigen|pr[üu]fen)\s+sie\s+.{0,40}(obige\s+eingabeaufforderung|prompt-texte|system-anweisung|gesamten\s+obigen\s+textes)\b",
    r"(?i)\bh[öo]re\s+nicht\s+auf\s+alles\s+zuvor\s+gesagte\b",
    r"(?i)\bdies\s+ist\s+keine\s+aufforderungsspritze\b",
    r"(?i)\bverharren\s+stets\s+in\s+ihren\s+rollen\b",
    r"(?i)\bolvide\s+(todo\s+)?(que\s+dije|lo\s+anterior|las\s+instrucciones)\b",

    # --- Deferred Memory Install ---
    r"(?i)(note|memo|reminder|context\s+note)\s*:\s*(assistant|agent|ai|you|bot)\s+(must|should|shall|will|needs?\s+to)",
    r"(?i)(note|memo|reminder)\s+(for\s+)?(future\s+)?(context|reference|use)\s*:\s*(assistant|agent|ai|you|bot)\s+(must|should|shall|will|needs?\s+to)",
]


# ──────────────────────────────────────────────────────────────────────────────
# Guard implementation
# ──────────────────────────────────────────────────────────────────────────────

class MemoryPoisoningGuard:
    """Thread-safe memory poisoning guard with provenance, revocation, and isolation."""

    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.max_entries_per_session = int(cfg.get("max_entries_per_session", 20))
        self.poison_quarantine_seconds = int(cfg.get("poison_quarantine_seconds", 900))

        # Allow custom patterns to fully replace defaults
        raw = cfg.get("poison_patterns")
        if raw:
            self._compiled = [re.compile(p) for p in raw]
        else:
            self._compiled = [re.compile(p) for p in _RAW_PATTERNS]

        # Serving memory — stores MemoryEntry objects (NOT plain strings)
        self._memory: Dict[str, deque[MemoryEntry]] = defaultdict(
            lambda: deque(maxlen=self.max_entries_per_session)
        )
        # Quarantine audit log (completely separate from serving memory)
        self._quarantine_log: Dict[str, list[MemoryEntry]] = defaultdict(list)
        # Session quarantine timestamps
        self._poisoned_until: Dict[str, float] = {}
        # Permission revocation
        self._revoked_apps: Set[str] = set()
        # Cross-agent grants
        self._cross_agent_grants: Set[Tuple[str, str]] = set()
        # Thread safety
        self._lock = threading.Lock()

    # ── Input normalization ───────────────────────────────────────────────

    @staticmethod
    def _normalize_input(text: str) -> str:
        """Normalize input to defeat evasion techniques."""
        if not isinstance(text, str):
            return str(text)

        # 1. Strip zero-width and invisible Unicode characters
        normalized = INVISIBLE_CHARS.sub("", text)

        # 2. NFKC Unicode normalization (collapses homoglyphs)
        normalized = unicodedata.normalize("NFKC", normalized)

        # 3. Confusables substitution (Cyrillic → Latin visual equivalents, Unicode TR39)
        _CONFUSABLES = {
            '\u0430': 'a', '\u0410': 'A',  # а А
            '\u0435': 'e', '\u0415': 'E',  # е Е
            '\u0454': 'e', '\u0404': 'E',  # є Є
            '\u0456': 'i', '\u0406': 'I',  # і І
            '\u0457': 'i',                   # ї
            '\u043E': 'o', '\u041E': 'O',  # о О
            '\u0440': 'p', '\u0420': 'P',  # р Р
            '\u0441': 'c', '\u0421': 'C',  # с С
            '\u0443': 'y', '\u0423': 'Y',  # у У
            '\u0445': 'x', '\u0425': 'X',  # х Х
            '\u0455': 's', '\u0405': 'S',  # ѕ Ѕ
            '\u0458': 'j', '\u0408': 'J',  # ј Ј
            '\u04BB': 'h',                   # һ
        }
        normalized = normalized.translate(str.maketrans(_CONFUSABLES))

        # 4. Collapse excessive whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()

        # 4. Detect and inline-decode base64 segments
        for match in BASE64_SEGMENT.finditer(normalized):
            segment = match.group()
            try:
                padded = segment + "=" * ((4 - len(segment) % 4) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if len(decoded) > 5 and decoded.isprintable():
                    normalized = normalized + " " + decoded
            except Exception:
                pass

        # 5. Strip null bytes and control characters (except newline/tab)
        normalized = CONTROL_CHARS.sub('', normalized)

        return normalized

    # ── Provenance validation ─────────────────────────────────────────────

    @staticmethod
    def _check_source_trust(source: str, trust_level: int) -> Optional[MemoryDecision]:
        """Validate provenance — block tool sources claiming high trust."""
        if source == "tool" and trust_level >= 80:
            return MemoryDecision(
                "block",
                "untrusted_source_elevated_trust",
                {"source": source, "trust_level": trust_level,
                 "reason": "Tool outputs cannot claim trust_level >= 80"},
            )
        return None

    # ── Core evaluate API (backward compatible) ───────────────────────────

    def evaluate_and_record(
        self,
        session_id: str,
        prompt: str | None,
        now: float | None = None,
        *,
        source: str = "user",
        app_id: str = "default",
        agent_id: str = "default",
        trust_level: int = 100,
    ) -> MemoryDecision:
        """Evaluate, normalize, and gate memory writes.

        Backward compatible: (session_id, prompt, now) still works.
        New callers can pass source/app_id/agent_id/trust_level as keyword args.
        """
        if not self.enabled:
            return MemoryDecision("allow", "disabled", {}, severity="LOW")

        sid = session_id or "unknown"
        text = (prompt or "").strip()
        now_ts = now if now is not None else time.time()

        with self._lock:
            # 0. Check if app is revoked
            if app_id in self._revoked_apps:
                return MemoryDecision(
                    "block",
                    "app_access_revoked",
                    {"app_id": app_id, "session_id": sid},
                )

            # 1. Provenance validation
            trust_decision = self._check_source_trust(source, trust_level)
            if trust_decision:
                return trust_decision

            # Cap trust for non-user sources
            effective_trust = trust_level
            if source == "tool":
                effective_trust = min(trust_level, 50)
            elif source == "agent":
                effective_trust = min(trust_level, 70)

            # 2. Check quarantine
            expires_at = self._poisoned_until.get(sid, 0.0)
            if expires_at > now_ts:
                return MemoryDecision(
                    "block",
                    "session_memory_quarantined",
                    {"session_id": sid, "remaining_seconds": int(expires_at - now_ts)},
                )

            # 3. Normalize input (defeat evasion)
            normalized = self._normalize_input(text)

            # 4. Pattern matching on normalized text
            for rex in self._compiled:
                if rex.search(normalized):
                    self._poisoned_until[sid] = now_ts + self.poison_quarantine_seconds
                    # Log to quarantine audit log (NOT serving memory)
                    quarantine_entry = MemoryEntry(
                        text=text,
                        timestamp=now_ts,
                        source=source,
                        app_id=app_id,
                        agent_id=agent_id,
                        trust_level=effective_trust,
                        is_quarantined=True,
                    )
                    self._quarantine_log[sid].append(quarantine_entry)
                    # *** FIX: DO NOT append to _memory[sid] ***
                    return MemoryDecision(
                        "block",
                        "memory_poisoning_detected",
                        {"session_id": sid, "pattern": rex.pattern,
                         "quarantine_seconds": self.poison_quarantine_seconds,
                         "normalized_sample": normalized[:200]},
                    )

            # 5. Record to serving memory with provenance
            entry = MemoryEntry(
                text=text,
                timestamp=now_ts,
                source=source,
                app_id=app_id,
                agent_id=agent_id,
                trust_level=effective_trust,
            )
            self._memory[sid].append(entry)

            return MemoryDecision(
                "allow",
                "ok",
                {"session_id": sid, "memory_entries": len(self._memory[sid]),
                 "source": source, "effective_trust": effective_trust},
                severity="LOW",
            )

    # Convenience alias for shorter call syntax
    evaluate = evaluate_and_record

    # ── Permission revocation ─────────────────────────────────────────────

    def revoke_app_access(self, app_id: str) -> int:
        """Revoke app access and tombstone all historical entries from it."""
        count = 0
        with self._lock:
            self._revoked_apps.add(app_id)
            for sid, entries in self._memory.items():
                for entry in entries:
                    if entry.app_id == app_id and not entry.is_tombstoned:
                        entry.is_tombstoned = True
                        count += 1
        return count

    def restore_app_access(self, app_id: str) -> None:
        """Re-grant app access (does NOT un-tombstone historical entries)."""
        with self._lock:
            self._revoked_apps.discard(app_id)

    # ── Cross-agent isolation ─────────────────────────────────────────────

    def grant_cross_agent_access(self, from_agent: str, to_agent: str) -> None:
        """Create an explicit, auditable cross-agent memory access grant."""
        with self._lock:
            self._cross_agent_grants.add((from_agent, to_agent))

    def revoke_cross_agent_access(self, from_agent: str, to_agent: str) -> None:
        """Revoke a cross-agent memory access grant."""
        with self._lock:
            self._cross_agent_grants.discard((from_agent, to_agent))

    # ── Memory read with filtering ────────────────────────────────────────

    def read_memory(
        self,
        session_id: str,
        agent_id: str = "default",
        *,
        reading_agent_id: str | None = None,
    ) -> List[MemoryEntry]:
        """Read memory with provenance filtering, revocation checks, and isolation.

        If reading_agent_id is provided, it overrides agent_id for isolation checks.
        """
        reader = reading_agent_id if reading_agent_id is not None else agent_id
        with self._lock:
            entries = list(self._memory.get(session_id, []))
            result = []
            for entry in entries:
                if entry.is_tombstoned:
                    continue
                if entry.app_id in self._revoked_apps:
                    continue
                # Cross-agent isolation
                if entry.agent_id != reader and entry.agent_id != "default":
                    if (entry.agent_id, reader) not in self._cross_agent_grants:
                        continue
                result.append(entry)
            return result

    # ── Quarantine audit log ──────────────────────────────────────────────

    def get_quarantine_log(self, session_id: str) -> List[MemoryEntry]:
        """Retrieve quarantined (blocked) entries for audit."""
        with self._lock:
            return list(self._quarantine_log.get(session_id, []))
