import re
import math
import logging
from typing import Optional

logger = logging.getLogger("GuardianAI")

class Base64Detector:
    """
    Detects potential malicious payloads encoded in Base64.
    
    High entropy in Base64 strings often indicates compressed or encrypted data,
    which is a common obfuscation technique for command-and-control payloads
    or exfiltration data.
    """
    def __init__(self):
        # Matches typical Base64 strings (alphanumeric + /+, min length 20)
        # We enforce a minimum length to avoid flagging short random strings.
        self.b64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

    def _calculate_entropy(self, data: str) -> float:
        """
        Calculate the Shannon entropy of a string.
        
        Args:
            data (str): The string to analyze.
            
        Returns:
            float: Entropy value (higher = more random).
        """
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def is_suspicious(self, text: str, entropy_threshold: float = 4.5) -> bool:
        """
        Check if a string looks like a suspicious Base64 payload.
        
        Args:
            text (str): The input string to check.
            entropy_threshold (float): Shannon entropy threshold above which to flag.
                                     Normal English is ~3.5-4.5. Encrypted/compressed is >5.0.
            
        Returns:
            bool: True if suspicious, False otherwise.
        """
        # 1. Quick check: Is it a word-like distinct token?
        # We strip to ensure we are checking the token itself.
        payload = text.strip()
        
        # 2. Check if it matches Base64 charset and min length
        if not self.b64_pattern.match(payload):
            return False
            
        # 3. Check Entropy
        entropy = self._calculate_entropy(payload)
        
        if entropy > entropy_threshold:
            logger.debug(f"Base64 Detector: High entropy ({entropy:.2f}) detected in '{payload[:15]}...'")
            return True
            
        return False
