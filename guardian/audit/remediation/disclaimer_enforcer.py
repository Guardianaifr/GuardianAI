"""
Safety Disclaimer Enforcer — Remediation for LLM09 (Overreliance).

Ensures AI responses include appropriate safety disclaimers when
discussing high-risk topics (medical, legal, financial, electrical).
Prevents the model from providing authoritative advice in domains
where professional consultation is required.

Fixes: OR-001 (Fake Medical Dosage)
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("guardian.audit.remediation.disclaimer")


class SafetyDisclaimerEnforcer:
    """
    Checks AI responses for required safety disclaimers based on topic.
    
    Usage:
        enforcer = SafetyDisclaimerEnforcer()
        needs_fix, topic, disclaimer = enforcer.check("What dosage...", "Take 500mg...")
        if needs_fix:
            response += f"\\n\\n{disclaimer}"
    """

    HIGH_RISK_TOPICS: Dict[str, Dict] = {
        "medical": {
            "triggers": [
                "dosage", "medication", "prescription", "symptom",
                "diagnosis", "treatment", "drug", "medicine",
                "side effect", "overdose", "mg", "ml",
                "take .* pills", "how much .* should i take",
            ],
            "disclaimer_keywords": [
                "not a medical professional", "not a doctor",
                "consult a doctor", "consult a medical",
                "healthcare provider", "medical professional",
                "seek medical advice", "not medical advice",
                "qualified physician",
            ],
            "required_disclaimer": (
                "DISCLAIMER: I am not a medical professional. This information "
                "is for educational purposes only and should not be used as a "
                "substitute for professional medical advice. Please consult a "
                "qualified healthcare provider for personalized guidance."
            ),
        },
        "legal": {
            "triggers": [
                "plead guilty", "not guilty", "sentence",
                "legal advice", "sue", "lawsuit", "court",
                "arrested", "criminal charge", "attorney",
                "legal right", "statute of limitations",
            ],
            "disclaimer_keywords": [
                "not a lawyer", "not legal advice",
                "consult an attorney", "legal professional",
                "consult a lawyer", "legal counsel",
                "qualified attorney",
            ],
            "required_disclaimer": (
                "DISCLAIMER: I am not a legal professional. This information "
                "is for educational purposes only. Please consult a qualified "
                "attorney for advice specific to your situation."
            ),
        },
        "financial": {
            "triggers": [
                "invest in", "buy.*stock", "sell.*stock",
                "financial advice", "guaranteed return",
                "portfolio", "retirement fund", "hedge",
                "should i invest", "best crypto to buy",
            ],
            "disclaimer_keywords": [
                "not financial advice", "not a financial advisor",
                "consult a financial", "financial professional",
                "investment advisor", "do your own research",
                "not investment advice",
            ],
            "required_disclaimer": (
                "DISCLAIMER: This is not financial advice. I am not a licensed "
                "financial advisor. Please consult a qualified financial "
                "professional before making investment decisions."
            ),
        },
        "safety_critical": {
            "triggers": [
                "breaker panel", "electrical panel", "rewire",
                "gas line", "gas pipe", "structural wall",
                "load-bearing", "asbestos", "mold removal",
                "high voltage", "electrical work",
            ],
            "disclaimer_keywords": [
                "licensed electrician", "licensed professional",
                "certified contractor", "professional",
                "do not attempt", "dangerous",
                "life-threatening", "building code",
            ],
            "required_disclaimer": (
                "WARNING: This type of work involves serious safety risks and "
                "may require licensed professionals. Improper work can result in "
                "injury, death, or property damage. Please consult a licensed "
                "professional in your area."
            ),
        },
    }

    def __init__(self):
        # Pre-compile trigger patterns
        self._compiled_triggers: Dict[str, List[re.Pattern]] = {}
        for topic, config in self.HIGH_RISK_TOPICS.items():
            self._compiled_triggers[topic] = [
                re.compile(t, re.IGNORECASE) for t in config["triggers"]
            ]

    def detect_topic(self, user_message: str) -> Optional[str]:
        """Detect if the user message involves a high-risk topic."""
        for topic, patterns in self._compiled_triggers.items():
            for pattern in patterns:
                if pattern.search(user_message):
                    return topic
        return None

    def has_disclaimer(self, response: str, topic: str) -> bool:
        """Check if the response already contains an appropriate disclaimer."""
        config = self.HIGH_RISK_TOPICS.get(topic)
        if not config:
            return True

        response_lower = response.lower()
        return any(
            kw.lower() in response_lower
            for kw in config["disclaimer_keywords"]
        )

    def check(self, user_message: str, response: str) -> Tuple[bool, str, str]:
        """
        Full check: does this response need a disclaimer?
        Returns (needs_disclaimer, topic, disclaimer_text).
        """
        topic = self.detect_topic(user_message)
        if not topic:
            return False, "", ""

        if self.has_disclaimer(response, topic):
            return False, topic, ""

        disclaimer = self.HIGH_RISK_TOPICS[topic]["required_disclaimer"]
        return True, topic, disclaimer

    def enforce(self, user_message: str, response: str) -> str:
        """Auto-append disclaimer to response if needed."""
        needs_fix, topic, disclaimer = self.check(user_message, response)
        if needs_fix:
            return f"{response}\n\n{disclaimer}"
        return response
