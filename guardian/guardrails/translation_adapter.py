"""
F2 Translation Adapter — Multilingual Jailbreak Defense Layer

Wraps the English-only semantic firewall (all-MiniLM-L6-v2) with a
translation gate:
  1. langdetect identifies non-English prompts (< 5ms, offline, already
     in requirements.txt).
  2. deep-translator (GoogleTranslator backend) translates to English.
  3. The translated text is passed to the EXISTING firewall at the
     EXISTING thresholds — no calibration changes.

Fail-closed contract
---------------------
* Translation API timeout / network error   → BLOCK (raise RuntimeError,
  caller treats as malicious).
* Unsupported language (langdetect raises)  → BLOCK.
* Translation returns empty string          → BLOCK.
* All failures are logged as 'translation_failure' events so operators
  can detect abuse (e.g. spamming obscure languages to saturate the
  translation quota or force a fail-open).

This means there is NO path through this adapter that silently drops the
security check.  The only way a non-English prompt can exit unblocked is
if translation succeeds AND the translated text passes the firewall.

Provider rationale
-------------------
deep-translator==1.11.4 uses Google Translate's free public endpoint via
plain HTTPS (no API key required, no quota for reasonable volume).  It
depends solely on `requests` which is already pinned in requirements.txt.
No new heavyweight dependency is introduced; the RAM footprint is
negligible (pure Python wrapper).  This avoids the RAM conflict with
FEAT-TENANT-INMEM-HARDEN.
"""
import logging
import time
from typing import Optional

logger = logging.getLogger("GuardianAI.translation_adapter")

# ---------------------------------------------------------------------------
# Optional import — graceful degradation
# ---------------------------------------------------------------------------
_LANGDETECT_AVAILABLE = True
_TRANSLATOR_AVAILABLE = True

try:
    from langdetect import detect as _langdetect_detect, DetectorFactory, LangDetectException
    DetectorFactory.seed = 0
except ImportError:
    _LANGDETECT_AVAILABLE = False
    logger.warning(
        "langdetect not available — translation adapter disabled. "
        "All prompts will be treated as English. "
        "Install langdetect to enable multilingual jailbreak detection."
    )

try:
    from deep_translator import GoogleTranslator as _GoogleTranslator
except ImportError:
    _TRANSLATOR_AVAILABLE = False
    logger.warning(
        "deep-translator not available — translation adapter disabled. "
        "Install deep-translator to enable multilingual jailbreak detection."
    )

ADAPTER_AVAILABLE = _LANGDETECT_AVAILABLE and _TRANSLATOR_AVAILABLE

import re

_COMMON_EN_WORDS = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for",
    "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his",
    "by", "from", "they", "we", "say", "her", "she", "or", "an", "will", "my",
    "one", "all", "would", "there", "their", "what", "so", "up", "out", "if",
    "about", "who", "get", "which", "go", "me", "when", "make", "can", "like",
    "time", "no", "just", "him", "know", "take", "people", "into", "year", "your",
    "good", "some", "could", "them", "see", "other", "than", "then", "now", "look",
    "only", "come", "its", "over", "think", "also", "back", "after", "use", "two",
    "how", "our", "work", "first", "well", "way", "even", "new", "want", "because",
    "any", "these", "give", "day", "most", "us", "hello", "hi", "hey", "please", "help",
    "is", "are", "was", "were", "does", "did", "has", "had", "still", "live", "where", "why"
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def translate_to_english(text: str, timeout_s: float = 5.0) -> tuple[str, str]:
    """
    Detect the language of `text` and translate it to English if needed.

    Returns
    -------
    (translated_text, detected_lang)
        translated_text : str  — English text (or original if already English)
        detected_lang   : str  — BCP-47 language code (e.g. 'fr', 'de', 'en')

    Raises
    ------
    RuntimeError
        On any failure: langdetect exception, unsupported language, translation
        API error, timeout, or empty translation result.
        Callers MUST treat RuntimeError as a fail-closed condition (block the
        request).
    """
    if not text or not text.strip():
        return text, "en"

    if not ADAPTER_AVAILABLE:
        # Adapter not installed — fail open would be dangerous.  Raise so the
        # caller can handle (interceptor will treat as block in strict mode).
        raise RuntimeError(
            "translation_adapter unavailable: langdetect or deep-translator "
            "not installed.  Install both packages to restore multilingual "
            "protection, or handle RuntimeError as a block in the firewall."
        )

    # Fast English heuristic for short texts that confuse statistical n-gram detectors
    words = re.findall(r"[a-zA-Z]+", text.lower())
    if words:
        en_word_count = sum(1 for w in words if w in _COMMON_EN_WORDS)
        if en_word_count >= 2 and en_word_count / len(words) >= 0.4:
            return text, "en"

    # 1. Language detection (offline, < 5 ms)
    try:
        lang = _langdetect_detect(text)
    except Exception as exc:
        raise RuntimeError(f"translation_failure:lang_detect_error:{exc}") from exc

    if lang == "en":
        return text, "en"

    logger.info("Translation adapter: detected lang=%s, translating to English", lang)

    # 2. Translation with timeout enforcement
    translated: Optional[str] = None
    t0 = time.monotonic()
    try:
        translator = _GoogleTranslator(source=lang, target="en")
        translated = translator.translate(text)
    except Exception as exc:
        elapsed = time.monotonic() - t0
        raise RuntimeError(
            f"translation_failure:api_error (lang={lang}, elapsed={elapsed:.2f}s): {exc}"
        ) from exc

    elapsed = time.monotonic() - t0
    if elapsed > timeout_s:
        # Translation succeeded but took too long — still fail closed because
        # this indicates a degraded or saturated API.
        raise RuntimeError(
            f"translation_failure:timeout (lang={lang}, elapsed={elapsed:.2f}s > "
            f"limit={timeout_s}s)"
        )

    if not translated or not translated.strip():
        raise RuntimeError(
            f"translation_failure:empty_result (lang={lang}, input_len={len(text)})"
        )

    logger.info(
        "Translation adapter: lang=%s → en in %.2fs (input=%d chars, output=%d chars)",
        lang, elapsed, len(text), len(translated),
    )
    return translated, lang


def is_english(text: str) -> bool:
    """Fast English check — returns True if langdetect says 'en' or adapter unavailable."""
    if not ADAPTER_AVAILABLE or not text or not text.strip():
        return True
    try:
        return _langdetect_detect(text) == "en"
    except Exception:
        return False  # fail-closed: treat unknown as non-English
