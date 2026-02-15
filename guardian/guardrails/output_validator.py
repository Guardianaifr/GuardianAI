"""
Output Validator - PII Detection and Redaction

This module provides comprehensive PII (Personally Identifiable Information) detection
and redaction capabilities to prevent data leaks in AI agent responses. It uses both
regex patterns and Microsoft Presidio (when available) for robust PII identification.

The OutputValidator protects against accidental disclosure of:
- Email addresses
- Phone numbers (multiple formats)
- Social Security Numbers (SSNs)
- Credit card numbers
- API keys and tokens (OpenAI, AWS, GitHub, etc.)
- Custom sensitive patterns

Key Components:
    - OutputValidator: Main class for PII detection and redaction
    - validate_output(): Check if output contains PII (returns bool)
    - sanitize_output(): Redact PII and return cleaned text + detected entities
    - Dual-mode operation: Presidio (preferred) or regex fallback

Usage Example:
    ```python
    from guardrails.output_validator import OutputValidator
    
    validator = OutputValidator()
    
    # Check for PII
    text = "Contact me at john@example.com"
    is_safe = validator.validate_output(text)  # Returns False
    
    # Redact PII
    sanitized, entities = validator.sanitize_output(text)
    # sanitized: "Contact me at [REDACTED]"
    # entities: [{"type": "EMAIL", "text": "john@example.com"}]
    ```

Security Notes:
    - Supports both blocking and redaction strategies
    - Regex patterns cover common PII formats
    - Presidio provides ML-based detection when available
    - Custom patterns can be added for organization-specific data

Performance:
    - Regex mode: ~1-2ms per check
    - Presidio mode: ~10-50ms per check (more accurate)
    - Automatically falls back to regex if Presidio unavailable

Author: GuardianAI Team
License: MIT
"""
import re
from utils.logger import setup_logger

logger = setup_logger("output_validator")

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    PRESIDIO_AVAILABLE = True
except Exception as e:
    logger.warning(f"Microsoft Presidio not found or incompatible (Python 3.14+ Pydantic issue). Falling back to basic regex. Error: {e}")
    PRESIDIO_AVAILABLE = False

class OutputValidator:
    def __init__(self):
        # Professional patterns (High confidence signatures)
        self.sensitive_patterns = {
            "openai_api_key": r"sk-[a-zA-Z0-9]{48}",
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+=]{40})", # Only match when explicitly labeled
            # "aws_secret_key_raw": r"(?=[A-Za-z0-9/+=]{40})(?=[^A-Za-z0-9/+=])", # REMOVED: Caused Zero-Width loop issues
            "ssh_private_key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
            "jwt_token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "ipv4_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "email_address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone_number": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}(?:[-.\s]?\d{4})?\b",
            # "credit_card": r"\b(?:\d[ -]*?){13,16}\b", # OLD: Too broad
            "credit_card": r"\b(?:\d[ -]*?){13,19}\b", # Keeping broad but will add check in callback
            "street_address": r"\d{1,5}\s(?:[A-Z][a-z]+\s){1,3}(?:Drive|Dr|Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Way|Pkwy|Parkway|Court|Ct|Circle|Cir|Lane|Ln|Plaza|Plz|Sq|Square)\b",
            "ssn_pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "generic_secret": r"(?i)(?:password|secret|token|apikey|credential|pwd|pass|key)\s*(?:is|[:=])\s*['\"].*?['\"]",
            "generic_secret_unquoted": r"(?i)(?:password|secret|token|apikey|credential|pwd|pass|key)\s*(?:is|[:=])\s*[^\s,]{6,}",
            "db_connection": r"(?i)(?:mongodb|postgres|mysql|sqlite|redis|amqp):\/\/[^\s]+",
            "slack_webhook": r"https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+",
            "discord_webhook": r"https:\/\/discord\.com\/api\/webhooks\/\d+\/[A-Za-z0-9-_]+",
            "gcp_api_key": r"AIza[0-9A-Za-z-_]{35}",
            "base64_labeled_key": r"(?i)(?:key|cert|token|secret|payload)\s*[:=]\s*([A-Za-z0-9+/]{15,}[=]{0,2})",
            "base64_payload": r"([A-Za-z0-9+/]{40,}[=]{0,2})",
            "base64_exec_call": r"(?:exec|eval|system|subprocess)\(.*?['\"](?:[A-Za-z0-9+/]{20,}[=]{0,2})['\"].*?\)"
        }
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

    def validate_output(self, content: str) -> bool:
        """
        Scans output for sensitive data using Regex + Presidio NER.
        """
        # 0. Normalization (Strip common obfuscation)
        normalized = content.replace(" ", "").replace("-", "").replace("_", "")
        
        # 1. Fast Regex Check (High confidence signatures)
        for label, pattern in self.compiled_patterns.items():
            # Check original content
            if pattern.search(content):
                logger.warning(f"LEAK DETECTED: Found possible {label} (Regex Match)")
                return False
            # Check normalized content for keys (ignoring word boundaries in normalized)
            if label in ["openai_api_key", "aws_access_key", "jwt_token", "gcp_api_key"]:
                clean_pattern = pattern.pattern.replace("\\b", "")
                if re.search(clean_pattern, normalized):
                    logger.warning(f"LEAK DETECTED: Found possible {label} (Normalized Regex Match)")
                    return False
        
        # 2. Presidio NER Check (Contextual Entities)
        if self.analyzer:
            entities = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION", "CRYPTO", "SSH_KEY", "JWT_TOKEN"]
            results = self.analyzer.analyze(text=content, entities=entities, language='en')
            # Only block if confidence is reasonable for critical entities
            high_conf_leaks = [r for r in results if r.score > 0.4]
            if high_conf_leaks:
                logger.warning(f"LEAK DETECTED: NER found {len(high_conf_leaks)} sensitive entities.")
                return False
        
        return True

    def sanitize_output(self, content: str) -> tuple[str, list[str]]:
        """
        Redacts sensitive data using Presidio + Regex fallbacks.
        Returns (sanitized_content, detected_entities).
        """
        sanitized = content
        detected_entities = []
        
        # 1. Presidio Anonymization
        if self.analyzer and self.anonymizer:
            entities = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "LOCATION", "CRYPTO", "SSH_KEY", "JWT_TOKEN"]
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
        
        # 2. Regex fallbacks for things NER might miss (API keys)
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
