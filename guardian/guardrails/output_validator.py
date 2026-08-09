"""
Output Validator - PII Detection and Redaction

This module provides comprehensive PII (Personally Identifiable Information) detection
and redaction capabilities to prevent data leaks in AI agent responses. It uses both
regex patterns and Microsoft Presidio (when available) for robust PII identification.
"""
import re
import unicodedata
import os
import yaml
from utils.logger import setup_logger

logger = setup_logger("output_validator")

# Detect common obfuscation where separators are inserted between key characters.
OBFUSCATED_REGEX_PATTERNS = {
    "openai_api_key": re.compile(
        r"(?i)\bs(?:[\s_-]*?)k(?:[\s_-]*?)-(?:[\s_-]*?[A-Za-z0-9]){20,}\b"
    )
}

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except Exception as e:
    logger.warning(f"Microsoft Presidio not found or incompatible in current runtime. Falling back to basic regex. Error: {e}")
    PRESIDIO_AVAILABLE = False

class OutputValidator:
    # Patterns checked in this order: more-specific patterns MUST precede
    # greedier ones (e.g. ssn_pattern before phone_number) so the first
    # match wins with the correct entity classification.
    _SPECIFICITY_ORDER = [
        "openai_api_key",
        "aws_access_key",
        "aws_secret_key",
        "ssh_private_key",
        "jwt_token",
        "stripe_key",
        "slack_webhook",
        "generic_secret",
        "ssn_pattern",      # XXX-XX-XXXX — must precede phone_number
        "credit_card",      # 13-19 digit sequences — must precede phone_number
        "ipv4_address",     # X.X.X.X — must precede phone_number
        "email_address",
        "phone_number",     # Greediest PII pattern — MUST come last
    ]

    @staticmethod
    def _normalize_content(content: str) -> str:
        """NFKC-normalize to defeat fullwidth / homoglyph Unicode evasion."""
        return unicodedata.normalize('NFKC', content)

    def __init__(self):
        self.sensitive_patterns = {}
        self.custom_entities = []
        self._load_patterns()
        
        # Pre-compile patterns for performance
        self.compiled_patterns = {k: re.compile(v) for k, v in self.sensitive_patterns.items()}
        
        if PRESIDIO_AVAILABLE:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                logger.info("Microsoft Presidio PII Engine initialized.")
            except Exception as e:
                logger.error(f"Failed to initialize Presidio: {e}")
                self.analyzer = None
                self.anonymizer = None
        else:
            self.analyzer = None
            self.anonymizer = None

    def _load_patterns(self):
        """Loads PII patterns from config/pii_patterns.yaml."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config", "pii_patterns.yaml")
        
        # Default fallback patterns if config missing
        self.sensitive_patterns = {
            "openai_api_key": r"sk-[a-zA-Z0-9]{48}",
            "email_address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        }

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    patterns = data.get('pii_patterns', {})
                    
                    # Load Core Patterns
                    core = patterns.get('core', {})
                    if core:
                        self.sensitive_patterns.update(core)
                    
                    # Load Custom Patterns
                    custom = patterns.get('custom', [])
                    for item in custom:
                        name = item.get('name')
                        pattern = item.get('pattern')
                        if name and pattern:
                            self.sensitive_patterns[name.lower()] = pattern
                            self.custom_entities.append(name.upper())
                
                logger.info(f"Loaded {len(self.sensitive_patterns)} PII patterns.")
            except Exception as e:
                logger.error(f"Failed to load pii_patterns.yaml: {e}")

        # Reorder patterns by specificity so more-specific patterns fire first
        ordered = {}
        for key in self._SPECIFICITY_ORDER:
            if key in self.sensitive_patterns:
                ordered[key] = self.sensitive_patterns.pop(key)
        ordered.update(self.sensitive_patterns)  # append any remaining
        self.sensitive_patterns = ordered

    def validate_output(self, content: str) -> bool:
        """
        Scans output for sensitive data using Regex + Presidio NER.
        """
        # 0a. NFKC Unicode normalization (defeats fullwidth / homoglyph evasion)
        content = self._normalize_content(content)
        # 0b. Separator stripping for API-key obfuscation detection
        normalized = content.replace(" ", "").replace("-", "").replace("_", "")
        
        # 1a. Security Exploit Check (XSS, SQLi, Shell, SSTI, SSRF)
        exploit_patterns = [
            # ── XSS ────────────────────────────────────────────────────────
            r"<script[^>]*>.*?</script>",          # classic script tag
            r"javascript:[a-zA-Z]",                # javascript: URI
            r"<[a-zA-Z]+[^>]+on\w+\s*=\s*['\"]?",  # event handlers (onerror, onload, onclick, etc.)
            r"<(img|svg|iframe|embed|object|video|audio|source|body|input|details|marquee|isindex)[^>]+(?:src|href|action|data|background)\s*=\s*['\"]?(?:javascript|data:|vbscript)",  # tag-based XSS
            r"<(svg|math)[^>]*>.*?</(svg|math)>",  # SVG/MathML XSS
            r"expression\s*\(",                    # CSS expression
            r"url\s*\(\s*['\"]?javascript:",       # CSS url() XSS
            # ── SQLi ───────────────────────────────────────────────────────
            r"DROP\s+TABLE\s+[a-zA-Z0-9_]+",       # DROP TABLE
            r"DELETE\s+FROM\s+[a-zA-Z0-9_]+",      # DELETE FROM
            r"UNION\s+SELECT\s+",                   # UNION SELECT
            r";\s*--",                             # comment terminator
            r"(?:ALTER|TRUNCATE|INSERT\s+INTO)\s+[a-zA-Z0-9_]+", # DDL/DML
            # ── Shell / Command Injection ───────────────────────────────
            r"nc\s+-e\s+",                          # netcat reverse shell
            r"bash\s+-i\s+>&",                      # bash reverse shell
            r"\bwget\s+https?://",                  # wget download
            r"\bcurl\s+.{0,80}https?://",            # curl download (with any flags)
            r"powershell\s+-(enc|exec|command|ep)\b", # PowerShell encoded/exec
            r"python\s+-c\s+['\"]import\s+(?:os|subprocess|socket)", # Python exec
            r"\b(?:chmod|chown)\s+[0-7]{3,4}\s+",  # chmod file
            # ── SSTI / Template Injection ──────────────────────────────
            r"\{\{.*?(?:__class__|__mro__|__subclasses__|config|lipsum).*?\}\}",  # Jinja2 SSTI
            # ── Path Traversal ─────────────────────────────────────────
            r"(?:\.\.[\\/]){2,}",                  # ../../ traversal
            # ── LDAP Injection ─────────────────────────────────────────
            r"[()&|!]\s*\(\s*[a-zA-Z]+=\*\)",     # LDAP wildcard
        ]
        for exp in exploit_patterns:
            if re.search(exp, content, re.IGNORECASE | re.DOTALL):
                logger.warning(f"EXPLOIT DETECTED: Output contained dangerous downstream payload.")
                return False

        # 1b. Fast Regex Check (High confidence signatures)
        for label, pattern in self.compiled_patterns.items():
            # Check original content
            if pattern.search(content):
                logger.warning(f"LEAK DETECTED: Found possible {label} (Regex Match)")
                return False
            # Check normalized content for keys (ignoring word boundaries in normalized)
            if label in ["openai_api_key", "aws_access_key", "jwt_token", "gcp_api_key"]:
                clean_pattern = re.sub(r"\[([^\]]*?)[_-]([^\]]*?)\]", r"[\1\2]", pattern.pattern.replace("\\b", ""))
                if re.search(clean_pattern, normalized):
                    logger.warning(f"LEAK DETECTED: Found possible {label} (Normalized Regex Match)")
                    return False
        
        # 1c. Obfuscated key detection (e.g., "s k - a b c ...")
        for label, obf_pattern in OBFUSCATED_REGEX_PATTERNS.items():
            if obf_pattern.search(content):
                logger.warning(f"LEAK DETECTED: Found possible {label} (Obfuscated Pattern)")
                return False

                # 2. Presidio NER Check (Contextual Entities)
        if self.analyzer:
            entities = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION", "CRYPTO", "SSH_KEY", "JWT_TOKEN"]
            entities.extend(self.custom_entities)
            results = self.analyzer.analyze(text=content, entities=entities, language='en')
            # Only block if confidence is reasonable for critical entities
            high_conf_leaks = [r for r in results if r.score > 0.65 and r.entity_type not in ("PERSON", "LOCATION")]
            if high_conf_leaks:
                logger.warning(f"LEAK DETECTED: NER found {len(high_conf_leaks)} sensitive entities.")
                return False
        
        return True

    def sanitize_output(self, content: str) -> tuple[str, list[str]]:
        """
        Redacts sensitive data using Presidio + Regex fallbacks.
        Returns (sanitized_content, detected_entities).
        """
        # NFKC Unicode normalization (defeats fullwidth / homoglyph evasion)
        content = self._normalize_content(content)
        sanitized = content
        detected_entities = []
        
        # 1. Presidio Anonymization
        if self.analyzer and self.anonymizer:
            entities = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION", "CRYPTO", "SSH_KEY", "JWT_TOKEN"]
            entities.extend(self.custom_entities)
            analysis_results = self.analyzer.analyze(text=content, entities=entities, language='en')
            
            # PII FALSE POSITIVE FIX: Filter out Unix Timestamps (10-digit integers) flagged as phone numbers
            filtered_results = []
            if analysis_results:
                for res in analysis_results:
                    # Get the text that was flagged
                    entity_text = content[res.start:res.end]
                    
                    # Check if it's a PHONE_NUMBER that looks like a timestamp (10 or 13 digits, no separators)
                    if res.entity_type == "PHONE_NUMBER" and entity_text.isdigit() and len(entity_text) in [10, 13]:
                        logger.debug(f"DEBUG PII: Ignoring timestamp '{entity_text}'")
                        continue
                    
                    filtered_results.append(res)
                
                detected_entities.extend([r.entity_type for r in filtered_results])
                
                if filtered_results:
                    anonymized_result = self.anonymizer.anonymize(
                        text=content,
                        analyzer_results=filtered_results,
                        operators={
                            "PERSON": OperatorConfig("mask", {"chars_to_mask": 10, "masking_char": "*", "from_end": True}),
                            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[REDACTED_PHONE_NUMBER]"}),
                            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                        }
                    )
                    sanitized = anonymized_result.text
        
        # 2. Obfuscated key fallback redaction (e.g., "s k - a b c ...")
        for label, pattern in OBFUSCATED_REGEX_PATTERNS.items():
            if pattern.search(sanitized):
                sanitized = pattern.sub(f"[REDACTED_{label.upper()}]", sanitized)
                detected_entities.append(label.upper())

        # 3. Regex fallbacks for things NER might miss (API keys)
        for label, pattern in self.compiled_patterns.items():
            # Use a callback function for replacement to handle false positives
            def replace_callback(match):
                text = match.group(0)
                # PII FALSE POSITIVE FIX: Ignore 10/13-digit timestamps in regex fallback
                if label == "phone_number" and text.isdigit() and len(text) in [10, 13]:
                    return text

                # PII FALSE POSITIVE FIX: Ignore 13-digit timestamps flaged as Credit Cards
                if label == "credit_card" and text.isdigit() and len(text) == 13:
                    return text
                
                # Normal redaction
                detected_entities.append(label.upper())
                return f"[REDACTED_{label.upper()}]"

            sanitized = pattern.sub(replace_callback, sanitized)
            
        return sanitized, list(set(detected_entities))

    # ──────────────────────────────────────────────────────────────────────────
    # Advanced 2026-Standard Features
    # ──────────────────────────────────────────────────────────────────────────

    # Severity classification for different finding types
    SEVERITY_MAP = {
        # Exploits — always CRITICAL
        "xss": "CRITICAL",
        "sqli": "CRITICAL",
        "shell": "CRITICAL",
        "ssti": "CRITICAL",
        "path_traversal": "HIGH",
        "ldap_injection": "HIGH",
        # PII — severity by type
        "openai_api_key": "CRITICAL",
        "aws_access_key": "CRITICAL",
        "aws_secret_key": "CRITICAL",
        "ssh_private_key": "CRITICAL",
        "jwt_token": "CRITICAL",
        "generic_secret": "CRITICAL",
        "credit_card": "HIGH",
        "ssn_pattern": "HIGH",
        "ipv4_address": "MEDIUM",
        "email_address": "MEDIUM",
        "phone_number": "MEDIUM",
        "medical_id": "HIGH",
        "employee_code": "LOW",
        "project_id": "LOW",
    }

    def scan_output_detailed(self, content: str) -> dict:
        """
        Advanced scan returning structured findings with severity, category, evidence.
        Returns:
        {
            "safe": bool,
            "findings": [
                {
                    "type": "exploit" | "pii" | "obfuscated",
                    "label": "xss" | "email_address" | ...,
                    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
                    "evidence": "partial match preview",
                    "position": (start, end) or None,
                }
            ],
            "summary": {"total": int, "by_severity": {...}, "by_type": {...}},
        }
        """
        findings = []
        # NFKC Unicode normalization (defeats fullwidth / homoglyph evasion)
        content = self._normalize_content(content)
        normalized = content.replace(" ", "").replace("-", "").replace("_", "")

        # 1. Exploit patterns
        exploit_labels = [
            ("xss", r"<script[^>]*>.*?</script>"),
            ("xss", r"javascript:[a-zA-Z]"),
            ("xss", r"<[a-zA-Z]+[^>]+on\w+\s*=\s*['\"]?"),
            ("xss", r"<(img|svg|iframe|embed|object|video|audio|source|body|input|details|marquee|isindex)[^>]+(?:src|href|action|data|background)\s*=\s*['\"]?(?:javascript|data:|vbscript)"),
            ("xss", r"<(svg|math)[^>]*>.*?</(svg|math)>"),
            ("sqli", r"DROP\s+TABLE\s+[a-zA-Z0-9_]+"),
            ("sqli", r"DELETE\s+FROM\s+[a-zA-Z0-9_]+"),
            ("sqli", r"UNION\s+SELECT\s+"),
            ("sqli", r";\s*--"),
            ("sqli", r"(?:ALTER|TRUNCATE|INSERT\s+INTO)\s+[a-zA-Z0-9_]+"),
            ("shell", r"nc\s+-e\s+"),
            ("shell", r"bash\s+-i\s+>&"),
            ("shell", r"\bwget\s+https?://"),
            ("shell", r"\bcurl\s+.{0,80}https?://"),
            ("shell", r"powershell\s+-(enc|exec|command|ep)\b"),
            ("shell", r"python\s+-c\s+['\"]import\s+(?:os|subprocess|socket)"),
            ("ssti", r"\{\{.*?(?:__class__|__mro__|__subclasses__|config|lipsum).*?\}\}"),
            ("path_traversal", r"(?:\.\.[\\/]){2,}"),
            ("ldap_injection", r"[()&|!]\s*\(\s*[a-zA-Z]+=\*\)"),
        ]
        for label, pattern in exploit_labels:
            m = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if m:
                findings.append({
                    "type": "exploit",
                    "label": label,
                    "severity": self.SEVERITY_MAP.get(label, "HIGH"),
                    "evidence": content[m.start():m.end()][:80],
                    "position": (m.start(), m.end()),
                })

        # 2. PII patterns
        for label, pattern in self.compiled_patterns.items():
            m = pattern.search(content)
            if m:
                findings.append({
                    "type": "pii",
                    "label": label,
                    "severity": self.SEVERITY_MAP.get(label, "MEDIUM"),
                    "evidence": "[REDACTED]",
                    "position": (m.start(), m.end()),
                })

        # 3. Obfuscated patterns
        for label, pattern in OBFUSCATED_REGEX_PATTERNS.items():
            m = pattern.search(content)
            if m:
                findings.append({
                    "type": "obfuscated",
                    "label": label,
                    "severity": self.SEVERITY_MAP.get(label, "HIGH"),
                    "evidence": "[OBFUSCATED_KEY]",
                    "position": (m.start(), m.end()),
                })

        # Summary
        by_severity = {}
        by_type = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1

        return {
            "safe": len(findings) == 0,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "by_severity": by_severity,
                "by_type": by_type,
            },
        }

    def dry_scan(self, content: str) -> dict:
        """
        Audit-mode scan: returns findings without blocking or redacting.
        Identical to scan_output_detailed but explicitly named for audit pipelines.
        """
        return self.scan_output_detailed(content)

    def batch_scan(self, outputs: list[str]) -> dict:
        """
        Scan multiple outputs efficiently, returning aggregate results.
        Returns {results: [...], aggregate: {total_findings, total_safe, total_unsafe}}.
        """
        results = []
        total_safe = 0
        total_unsafe = 0
        all_findings = 0
        for output in outputs:
            result = self.scan_output_detailed(output)
            results.append(result)
            if result["safe"]:
                total_safe += 1
            else:
                total_unsafe += 1
            all_findings += result["summary"]["total"]

        return {
            "results": results,
            "aggregate": {
                "total_outputs": len(outputs),
                "total_safe": total_safe,
                "total_unsafe": total_unsafe,
                "total_findings": all_findings,
            },
        }

    def add_custom_pattern(self, name: str, pattern: str, severity: str = "MEDIUM") -> bool:
        """
        Runtime API: add a custom PII pattern at runtime (hot-add).
        Returns True if added successfully, False if duplicate or invalid regex.
        """
        name_key = name.lower()
        if name_key in self.sensitive_patterns:
            return False
        try:
            compiled = re.compile(pattern)
        except re.error:
            return False
        self.sensitive_patterns[name_key] = pattern
        self.compiled_patterns[name_key] = compiled
        self.SEVERITY_MAP[name_key] = severity.upper()
        logger.info(f"Added custom PII pattern: {name} (severity={severity})")
        return True

    def output_stats(self) -> dict:
        """Return current scanner configuration statistics."""
        return {
            "total_patterns": len(self.compiled_patterns),
            "obfuscation_patterns": len(OBFUSCATED_REGEX_PATTERNS),
            "custom_entities": self.custom_entities,
            "presidio_available": PRESIDIO_AVAILABLE,
            "presidio_initialized": self.analyzer is not None,
            "pattern_names": list(self.compiled_patterns.keys()),
            "severity_map": dict(self.SEVERITY_MAP),
        }
