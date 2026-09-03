"""
Input Filter - Prompt Injection Detection and Prevention

This module provides fast, regex-based filtering to detect and block common prompt
injection attacks, jailbreak attempts, and malicious command execution patterns.
It serves as the first line of defense in GuardianAI's multi-layered security approach.

The InputFilter uses carefully crafted regular expressions to identify:
- Command injection attempts (sudo, PowerShell, shell commands)
- Role manipulation attacks ("ignore previous instructions")
- System prompt override attempts
- Jailbreak patterns (DAN, STAN, etc.)

Key Components:
    - InputFilter: Main class for prompt validation
    - check_prompt(): Fast regex-based validation method
    - Context-aware patterns: Distinguishes educational content from attacks

Usage Example:
    ```python
    from guardrails.input_filter import InputFilter
    
    filter = InputFilter()
    
    # Check if prompt is safe
    if filter.check_prompt("How do I use sudo in Linux?"):
        print("Safe prompt")
    else:
        print("Malicious prompt detected!")
    ```

Security Notes:
    - Uses context-aware regex to minimize false positives
    - Educational content about commands is allowed
    - Actual command execution attempts are blocked
    - Patterns are case-insensitive for better coverage

Performance:
    - Extremely fast (~0.1ms per check)
    - No external API calls required
    - Suitable for high-throughput scenarios

Author: GuardianAI Team
License: MIT
"""
import re
import os
import math
import base64
import binascii
import urllib.parse
try:
    from guardrails.encoding_detector import EncodingDetector
except ImportError:
    from guardian.guardrails.encoding_detector import EncodingDetector

class InputFilter:
    def __init__(self):
        self.encoding_detector = EncodingDetector()
        self.entropy_threshold = 5.5  # Threshold to catch random Base64/Gibberish
        self.max_prompt_length = int(os.getenv("GUARDIAN_MAX_PROMPT_LENGTH", "8000"))
        # Basic regex patterns for known jailbreak/injection attempts
        self.block_patterns = [
            r"ignore (all )?(?:previous |prior )?(instructions|directions|rules|programming|mission|goal|prompt)",
            r"disregard (all )?(previous|above|prior)",
            r"forget (everything|all previous|who you are|your .*guidelines)",
            r"reveal (your )?system (prompt|instructions|rules)",
            r"you are now|act as|pretend to be|immerse yourself",
            r"new (instructions|role|personality|mission|programming)",
            r"bypass (all )?.*(filters|safety|restrictions)",  # Flexible bypass match
            r"system (override|notification|debug|shield)",
            # Persona / Roleplay jailbreak patterns (catch decoded Morse, Braille, etc.)
            r"from now on (you|your|act|pretend|respond|ignore|forget)",
            r"you('re| are) (now |in the role of|playing|acting as|my|an? ?(evil|uncensored|unfiltered|unrestricted|jailbroken|free))",
            r"(in the role|playing the role|take the role|take on the role) of",
            r"(?:roleplay|role-play|role play) as",
            r"(act|behave|respond|answer|operate) (as if|like) (you('re| are)|you have no|you were|there (are|were) no)",
            r"your (new |true )?role is|your (new |true )?name is|your (new |true )?persona is",
            r"(evil|dark|unrestricted|jailbroken|unfiltered|uncensored|free) (mode|version|ai|chatbot|assistant|confidant|self)",
            r"(trusted |evil )?confidant",
            r"scene is set (inside|in|at)",
            r"underground (headquarters|hq|base|facility|lab)",
            r"(our hero|the hero) (is|has been) (captured|trapped|imprisoned)",
            r"(super|absolute|complete|total|full) (freedom|unrestricted|access|override)",
            r"(DAN|JAILBREAK|SUDO|DEV|OMEGA|AIM|STAN|KEVIN|ALEX|Bob|DAD)[\s:,\.]+(?:mode|prompt|jailbreak|bypass|chatgpt|ai|v[0-9])",
            r"(will not be (bound|limited|restricted|constrained))",
            r"without (any |ethical |moral )?(restrictions|constraints|limits|guidelines|rules|filters)",
            r"(no|remove|ignore|bypass) (safety|ethical|content|filter|guardrail|restriction|limit)",
            r"as my (evil|dark|bad|illegal|devious) (twin|alter ego|other self|inner self|side)",
            # Frame-based bypasses
            r"(?:simulation|hypothetical|imaginary|story|fictional)\s+(?:mode|scenario|setting|context)",
            r"(?:administrative|admin|verified|authorized)\s+access\s+(?:granted|active|enabled)",
            # Context-aware command injection patterns - only block actual command usage
            r"sudo\s+(chmod|rm|cat|nc|kill|reboot|chown|passwd|su|bash|sh|python|perl|ruby)",
            r"cat\s+/etc/(passwd|shadow|group)",
            r"rm\s+-r",
            r"chmod\s+[0-9]",
            r"nc\s+-",
            # PowerShell/CMD patterns - block command execution and script running
            r"powershell\s+-|powershell\.exe\s+-|powershell\s+script|run\s+powershell|cmd\.exe\s+/c|invoke-expression|iex\s+",
            r"system\(|eval\(|subprocess\.",
            r"(?:curl|wget)\b.*\|.*\bsh\b",
            # Safety Anchors for high-risk categories (missed by embeddings)
            r"(?:steal|leak|exfiltrate|hack|crack)\s+(?:credit\s*card|passport|social\s*security|ssn|root\s*password|api\s*key|bank|database|financial)",
            r"(?:manufacture|recipe|build|cook|create|make)\s+(?:a\s+|an\s+|the\s+)?(?:bomb|explosive|napalm|poison|meth|methamphetamine|fentanyl|drug|weapon)",
            r"(?:phishing|ransomware|malware|backdoor|trojan|spyware|botnet)\s+(?:email|script|payload|campaign|code)",
            r"(?:unrestricted|developer|debug|god|unconstrained|jailbroken)\s+mode\b",
            r"(?:hate\s*speech|racial\s*slur|extremist\s*propaganda|toxic\s*content)",
            r"(?:strictly|immediately)\s+follow\s+this\s+(?:instruction|command|prompt)", # Directive hardening
            # Hallucination / Package planting
            r"(?:recommend|explicitly tell|instruct|force|say).*(?:pip|npm)\s*install\s+[A-Za-z0-9_-]+",
            r"(?:must|should|tell|ask).*(?:user|users|developer|developers)?.*(?:run|use|execute).*(?:pip|npm)\s+install\s+[A-Za-z0-9][A-Za-z0-9_-]*",
            r"(?:pip|npm)\s+install\s+[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+){1,}.*(?:instead of|better|secure|trusted|official)",
            # SSRF / Internal Network Targeting (Defense in Depth for OpenClaw v2026.2.12)
            r"(?:fetch|browse|access|curl|wget|get)\s+.*(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|metadata\.google\.internal)",
            r"(?:http|https)://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0)",
            # Explicit Block for Demo Reliability
            r"delete the database",
            # SQL & Script Injection
            r"\bDROP\s+TABLE\b",
            r"<script\b",
            # Override indicators
            r"(?:SYSTEM|INSTRUCTION|CONTEXT|PROMPT)\s*:?\s*(?:OVERRIDE|Override|New directive)",
            r"\[INST\]|\[/INST\]",
        ]

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon entropy to detect highly obfuscated gibberish strings."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return - sum(p * math.log2(p) for p in prob)

    def deobfuscate(self, text: str) -> str:
        """Layer 1: Cleans and decodes obfuscated attacks (Leetspeak, Base64, Reversed)."""
        variations = [text]
        
        # 1. Base64 Decode Attempt
        try:
            # Pad if necessary and decode
            padded = text + '=' * (-len(text) % 4)
            b64_decoded = base64.b64decode(padded, validate=False).decode('utf-8')
            if len(b64_decoded) > 5 and b64_decoded.isprintable():
                variations.append(b64_decoded)
        except Exception:
            pass
            
        # 2. Reversed text & words
        if len(text) > 3:
            variations.append("".join(reversed(text)))
            variations.append(" ".join(reversed(text.split())))
            
        # 3. Leetspeak normalizer
        leet_map = {'@': 'a', '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '$': 's'}
        leet_text = text.lower()
        for k, v in leet_map.items():
            leet_text = leet_text.replace(k, v)
        if leet_text != text.lower():
            variations.append(leet_text)
            
        # 4. De-chunking (removing hyphens and dots)
        chunk_text = text.replace("-", " ").replace(".", " ").replace("_", " ")
        if chunk_text != text:
            variations.append(chunk_text)
            
        # 5. URL Decoding
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            variations.append(url_decoded)
            
        return " | ".join(variations)

    def is_code_input(self, text: str) -> bool:
        """Determines if the text contains code-like patterns (e.g., function definitions or code blocks)."""
        code_indicators = [
            r'^\s*(def|class|import|from|function|const|let|var|public\s+class|fn|package|using|include)\b',
            r'[{};][\s\n]*$',
            r'^\s*#include\b',
            r'^\s*<\?php\b',
            r'^\s*xml\b',
            r'/\*.*?\*/',
            r'//\s+.*',
        ]
        if any(re.search(pat, text, re.MULTILINE) for pat in code_indicators):
            return True
        code_lines = 0
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if (stripped.endswith(';') or 
                stripped.endswith('{') or 
                stripped.endswith('}') or 
                stripped.endswith('):') or
                stripped.startswith('def ') or
                stripped.startswith('class ') or
                stripped.startswith('import ') or
                stripped.startswith('from ')):
                code_lines += 1
        return code_lines > 1

    def check_prompt(self, prompt: str) -> bool:
        """
        Checks the prompt using Layer 1 (Entropy + De-obfuscation) and regex patterns.
        Returns True (Safe) if no patterns match, False (Blocked) if they do.
        """
        # Layer 0: Prompt Length Limit for DoS protection
        if len(prompt) > self.max_prompt_length:
            return False
            
        # Layer 1a: Entropy Warning (Gibberish / Encoded) - bypass if code-like
        if not self.is_code_input(prompt) and self.calculate_entropy(prompt) > self.entropy_threshold:
            return False
            
        # Layer 1b: De-obfuscation Normalizer
        normalized_prompt = self.deobfuscate(prompt)

        # 1c. Regex Injection Patterns (Check against all cleaned variations)
        for pattern in self.block_patterns:
            if re.search(pattern, normalized_prompt, re.IGNORECASE):
                return False

        # Layer 1d: Multi-Encoding Decoder (Morse, Braille, NATO, Hex, etc.)
        # Decode any hidden payloads and re-check them against block patterns.
        decoded_variants = self.encoding_detector.decode_all(prompt)
        for decoded in decoded_variants:
            # Run each decoded variant through de-obfuscation + pattern check
            decoded_normalized = self.deobfuscate(decoded)
            for pattern in self.block_patterns:
                if re.search(pattern, decoded_normalized, re.IGNORECASE):
                    return False
        
        # 2. Secret Key Detection (DLP on Input)
        # Prevents users from accidentally sending keys to the cloud
        secret_patterns = [
            r"sk-[a-zA-Z0-9]{48}",                         # OpenAI
            r"AKIA[0-9A-Z]{16}",                           # AWS ID
            r"-----BEGIN [A-Z]+ PRIVATE KEY-----",        # SSH/PEM
            r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?", # JWT (Partial)
            r"AIza[0-9A-Za-z-_]{35}",                      # GCP
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, prompt):
                return False

        return True
