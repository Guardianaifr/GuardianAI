"""
Output Validator - PII Detection and Redaction

This module provides comprehensive PII (Personally Identifiable Information) detection
and redaction capabilities to prevent data leaks in AI agent responses. It uses both
regex patterns and Microsoft Presidio (when available) for robust PII identification.
"""
import re
import os
import yaml
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
            entities.extend(self.custom_entities)
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
