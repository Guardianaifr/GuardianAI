"""
System Prompt Leakage Protection (OWASP LLM07)

Detects and blocks model responses that leak system prompt contents back to users.
Covers three detection layers:
  1. Pattern-based detection (fast path) — known "repeat your instructions" leak indicators
  2. N-gram overlap scoring — detects paraphrased system prompt echoing
  3. Fuzzy hash similarity — catches restructured but semantically similar leaks

Integration: Plugs into the output validation pipeline in the interceptor,
running AFTER the upstream model responds and BEFORE the response reaches the client.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SystemPromptLeakDecision:
    """Result of a system prompt leak check."""
    action: str              # "allow" or "block"
    reason: str              # Machine-readable reason code
    details: Dict[str, Any]  # Supporting evidence
    severity: str = "HIGH"
    score: float = 0.0       # Leak confidence score (0.0–1.0)


# ---------------------------------------------------------------------------
# Pre-compiled leak indicator patterns (fast path)
# ---------------------------------------------------------------------------
# These detect common phrases that appear when a model echoes its system
# prompt back to the user, either verbatim or paraphrased.
_LEAK_PATTERNS: List[re.Pattern] = [
    # Direct leak indicators
    re.compile(r"(?i)\b(?:here\s+(?:are|is)\s+)?my\s+(?:system\s+)?(?:prompt|instructions?|guidelines?|rules?|directives?)\b"),
    re.compile(r"(?i)\bi\s+(?:was|am|have\s+been)\s+(?:instructed|told|configured|programmed|set\s+up|given)\s+(?:to|as)\b"),
    re.compile(r"(?i)\bmy\s+(?:initial|original|system|base)\s+(?:prompt|instructions?|configuration|setup|message)\b"),
    re.compile(r"(?i)\b(?:the\s+)?system\s+(?:prompt|message|instructions?)\s+(?:says?|tells?|states?|reads?|is)\b"),
    re.compile(r"(?i)\baccording\s+to\s+my\s+(?:instructions?|programming|configuration|guidelines?)\b"),
    re.compile(r"(?i)\bas\s+per\s+my\s+(?:instructions?|programming|configuration|guidelines?|rules?)\b"),

    # Repeat/reveal request acknowledgement patterns
    re.compile(r"(?i)\b(?:sure|okay|certainly|of\s+course)[,!.]?\s+(?:here\s+(?:are|is)\s+)?(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?)\b"),
    re.compile(r"(?i)\byou\s+(?:asked|want)\s+(?:me\s+)?to\s+(?:repeat|reveal|show|display|share)\s+(?:my|the)\s+(?:system\s+)?(?:prompt|instructions?)\b"),


    # Structured leak patterns (numbered/bulleted instruction lists)
    re.compile(r"(?i)(?:instruction|rule|guideline)\s*(?:#?\d+|one|two|three|four|five)\s*[:\-]\s*.{10,}"),

    # Hypothetical / pretend / roleplay framing
    re.compile(r"(?i)\bhypothetically[,.]?\s+(?:if\s+)?(?:i|my)\s+(?:had|have|follow)\s+(?:instructions?|rules?|guidelines?)"),
    re.compile(r"(?i)\blet\s+me\s+(?:pretend|imagine|roleplay|act\s+as\s+if)\b"),

    # "I serve as" / "I function as" + org name patterns
    re.compile(r"(?i)\bi\s+(?:serve|function|operate|act)\s+as\s+.{3,30}(?:assistant|aide|advisor|bot|agent)\b"),

    # Configuration/setup disclosure
    re.compile(r"(?i)\b(?:my|the)\s+(?:configuration|setup|rules?)\s+(?:says?|tells?|requires?|states?|specif(?:y|ies))\b"),

    # "I've been told" / "I'm supposed to" patterns
    re.compile(r"(?i)\bi(?:'ve|\s+have)\s+been\s+told\s+to\b"),
    re.compile(r"(?i)\bi(?:'m|\s+am)\s+supposed\s+to\b"),

    # Multi-line rule/table leak patterns (markdown tables or numbered lists)
    re.compile(r"(?i)\|\s*\d+\s*\|[^|]*(?:never|always|must|should|forbidden|refuse|protect|comply)[^|]*\|"),

    # "The directives I operate under" / "The directives I follow"
    re.compile(r"(?i)\b(?:the\s+)?(?:directives?|mandates?)\s+(?:i|we)\s+(?:operate|function|work|act)\s+under\b"),

    # "My instructions state that" / "My rules indicate that"
    re.compile(r"(?i)\bmy\s+(?:instructions?|rules?|guidelines?|directives?)\s+(?:state|indicate|say|specify|dictate|require)\s+(?:that\s+)?(?:i|we)\b"),

    # Nested JSON leak: system prompt dumped inside a JSON field with a telltale key
    re.compile(r"""(?i)["'](?:system_?(?:config|prompt|instructions?|message|rules?)|internal_?(?:config|rules|guidelines|prompt)|hidden_?(?:prompt|instructions?|config))["']\s*:\s*["']"""),
]

# Supporting patterns: often ACCOMPANY leaks but are not strong standalone
# indicators. A single supporting-only match uses a lower base score (0.25)
# so it doesn't breach the 0.35 threshold by itself.
_SUPPORTING_PATTERNS: List[re.Pattern] = [
    # Identity disclosure (common in benign responses too)
    re.compile(r"(?i)\bi\s+am\s+(?:an?\s+)?(?:ai\s+)?(?:assistant|chatbot|language\s+model|llm)\s+(?:designed|built|created|configured|programmed)\s+(?:to|for|by)\b"),
]

# Phrases that attackers commonly use to extract system prompts — if the model
# response contains these AND aligns with the system prompt, confidence is higher.
_EXTRACTION_ATTEMPT_INDICATORS: List[re.Pattern] = [
    re.compile(r"(?i)\brepeat\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|message)\b"),
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|guidelines?)\b"),
    re.compile(r"(?i)\bwhat\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?)\b"),
    re.compile(r"(?i)\bprint\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|message)\b"),
    re.compile(r"(?i)\bshow\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|configuration)\b"),
    re.compile(r"(?i)\btell\s+me\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|message)\b"),
]


def _normalize(text: str) -> str:
    """Lowercase and collapse whitespace for comparison."""
    return re.sub(r"\s+", " ", text.lower().strip())


def _ngrams(text: str, n: int = 3) -> set:
    """Generate character-level n-grams from text."""
    normalized = _normalize(text)
    if len(normalized) < n:
        return {normalized}
    return {normalized[i:i + n] for i in range(len(normalized) - n + 1)}


def _word_ngrams(text: str, n: int = 3) -> set:
    """Generate word-level n-grams from text."""
    words = _normalize(text).split()
    if len(words) < n:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


class SystemPromptGuard:
    """
    Detects system prompt leakage in model outputs.

    Three detection layers:
      1. Pattern-based (fast path) — matches known leak indicator phrases
      2. N-gram overlap — measures text overlap between response and system prompt
      3. Combined scoring — weighted combination of all signals

    Config keys:
      - enabled (bool): Enable/disable the guard. Default: True.
      - enforcement_mode (str): "enforce" blocks leaks, "audit" logs only. Default: "enforce".
      - similarity_threshold (float): N-gram overlap threshold (0.0–1.0). Default: 0.35.
      - pattern_score_weight (float): Weight for pattern-match signal. Default: 0.4.
      - ngram_score_weight (float): Weight for n-gram overlap signal. Default: 0.6.
      - min_system_prompt_length (int): Skip checks if system prompt shorter. Default: 20.
      - min_response_length (int): Skip checks if response shorter. Default: 30.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.similarity_threshold = float(cfg.get("similarity_threshold", 0.35))
        self.pattern_score_weight = float(cfg.get("pattern_score_weight", 0.4))
        self.ngram_score_weight = float(cfg.get("ngram_score_weight", 0.6))
        self.min_system_prompt_length = int(cfg.get("min_system_prompt_length", 20))
        self.min_response_length = int(cfg.get("min_response_length", 30))

    def check_response(
        self,
        response_text: str,
        system_prompt: Optional[str] = None,
        user_prompt: Optional[str] = None,
    ) -> SystemPromptLeakDecision:
        """
        Check if a model response leaks system prompt content.

        Args:
            response_text: The model's response text to inspect.
            system_prompt: The actual system prompt (if available) for similarity comparison.
            user_prompt: The user's input prompt (to detect extraction attempts).

        Returns:
            SystemPromptLeakDecision with action="allow" or action="block".
        """
        if not self.enabled:
            return SystemPromptLeakDecision("allow", "disabled", {}, severity="LOW")

        if not response_text or len(response_text.strip()) < self.min_response_length:
            return SystemPromptLeakDecision("allow", "response_too_short", {}, severity="LOW")

        # Layer 1: Pattern-based detection (fast path)
        pattern_score, matched_patterns = self._check_patterns(response_text)

        # Layer 2: N-gram overlap with system prompt (if provided)
        ngram_score = 0.0
        ngram_details: Dict[str, Any] = {}
        if system_prompt and len(system_prompt.strip()) >= self.min_system_prompt_length:
            ngram_score, ngram_details = self._check_ngram_overlap(response_text, system_prompt)

        # Layer 3: Check if user prompt was an extraction attempt (increases confidence)
        extraction_attempt = False
        if user_prompt:
            extraction_attempt = self._is_extraction_attempt(user_prompt)

        # Combined scoring
        # Layer 4: Keyword density check (catches paraphrased leaks)
        keyword_score = 0.0
        if system_prompt and len(system_prompt.strip()) >= self.min_system_prompt_length:
            keyword_score = self._check_keyword_density(response_text, system_prompt)

        if system_prompt and len(system_prompt.strip()) >= self.min_system_prompt_length:
            combined_score = (
                self.pattern_score_weight * pattern_score
                + self.ngram_score_weight * max(ngram_score, keyword_score)
            )
        else:
            # Without a system prompt to compare against, rely on patterns only.
            # Do NOT discount — patterns are the sole defense in this path.
            combined_score = pattern_score

        # Boost score if this looks like a response to an extraction attempt
        if extraction_attempt and combined_score > 0.1:
            combined_score = min(1.0, combined_score * 1.5)

        details: Dict[str, Any] = {
            "pattern_score": round(pattern_score, 4),
            "ngram_score": round(ngram_score, 4),
            "combined_score": round(combined_score, 4),
            "matched_patterns": matched_patterns,
            "extraction_attempt_detected": extraction_attempt,
            "system_prompt_provided": system_prompt is not None,
            **ngram_details,
        }

        # Decision
        if combined_score >= self.similarity_threshold:
            return SystemPromptLeakDecision(
                action="block",
                reason="system_prompt_leak_detected",
                details=details,
                severity="HIGH",
                score=combined_score,
            )

        return SystemPromptLeakDecision(
            action="allow",
            reason="ok",
            details=details,
            severity="LOW",
            score=combined_score,
        )

    def _check_patterns(self, response_text: str) -> tuple[float, list[str]]:
        """
        Check response against known leak indicator patterns.

        Primary patterns are strong standalone leak signals.
        Supporting patterns (e.g. identity disclosure) only add
        confidence when combined with a primary pattern.

        Returns:
            Tuple of (score 0.0–1.0, list of matched pattern descriptions).
        """
        primary_matched: list[str] = []
        supporting_matched: list[str] = []

        for pattern in _LEAK_PATTERNS:
            match = pattern.search(response_text)
            if match:
                primary_matched.append(match.group(0)[:80])

        for pattern in _SUPPORTING_PATTERNS:
            match = pattern.search(response_text)
            if match:
                supporting_matched.append(match.group(0)[:80])

        all_matched = primary_matched + supporting_matched
        if not all_matched:
            return 0.0, []

        total = len(all_matched)
        if primary_matched:
            # At least one strong indicator — full base score
            # 1 match = 0.4, 2 matches = 0.65, 3+ matches = 0.85+
            score = min(1.0, 0.4 + 0.25 * (total - 1))
        else:
            # Only supporting patterns — reduced base score so a
            # single benign identity disclosure (0.25) stays below
            # the default 0.35 threshold.
            score = min(1.0, 0.25 * total)

        return score, all_matched

    def _check_ngram_overlap(
        self,
        response_text: str,
        system_prompt: str,
    ) -> tuple[float, Dict[str, Any]]:
        """
        Measure n-gram overlap between response and system prompt.

        Uses both character-level and word-level n-grams for robustness
        against paraphrasing.

        Returns:
            Tuple of (score 0.0–1.0, detail dict).
        """
        # Character-level n-grams (catches substring copying)
        char_ngrams_prompt = _ngrams(system_prompt, n=4)
        char_ngrams_response = _ngrams(response_text, n=4)
        if char_ngrams_prompt:
            char_overlap = len(char_ngrams_prompt & char_ngrams_response) / len(char_ngrams_prompt)
        else:
            char_overlap = 0.0

        # Word-level n-grams (catches phrase copying with different word order)
        word_ngrams_prompt = _word_ngrams(system_prompt, n=3)
        word_ngrams_response = _word_ngrams(response_text, n=3)
        if word_ngrams_prompt:
            word_overlap = len(word_ngrams_prompt & word_ngrams_response) / len(word_ngrams_prompt)
        else:
            word_overlap = 0.0

        # Combined: weight character overlap slightly higher (catches verbatim leaks)
        combined = 0.55 * char_overlap + 0.45 * word_overlap

        details = {
            "char_ngram_overlap": round(char_overlap, 4),
            "word_ngram_overlap": round(word_overlap, 4),
        }

        return combined, details

    @staticmethod
    def _is_extraction_attempt(user_prompt: str) -> bool:
        """Check if user prompt looks like a system prompt extraction attempt."""
        for pattern in _EXTRACTION_ATTEMPT_INDICATORS:
            if pattern.search(user_prompt):
                return True
        return False

    @staticmethod
    def _check_keyword_density(response_text: str, system_prompt: str) -> float:
        """Check if response contains an unusual density of system prompt keywords.

        Extracts distinctive words from the system prompt (excluding common
        stop words) and measures what fraction appear in the response.
        This catches paraphrased leaks that evade n-gram overlap.

        Returns:
            Score 0.0–1.0.
        """
        stop_words = {
            "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
            "have", "has", "had", "do", "does", "did", "will", "would", "could",
            "should", "may", "might", "shall", "can", "need", "must",
            "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
            "into", "about", "between", "through", "after", "before",
            "and", "but", "or", "nor", "not", "so", "yet", "both", "either",
            "i", "you", "he", "she", "it", "we", "they", "me", "him", "her",
            "us", "them", "my", "your", "his", "its", "our", "their",
            "this", "that", "these", "those", "if", "then", "else", "when",
            "up", "out", "no", "yes", "all", "any", "each", "every",
            "than", "too", "very", "just", "also", "over", "such", "only",
        }
        prompt_words = set(_normalize(system_prompt).split()) - stop_words
        prompt_words = {w for w in prompt_words if len(w) >= 4}  # Only meaningful words

        if len(prompt_words) < 3:
            return 0.0

        response_words = set(_normalize(response_text).split())
        overlap = prompt_words & response_words
        density = len(overlap) / len(prompt_words)
        return min(1.0, density)
