import re
import logging

logger = logging.getLogger("GuardianAI.fast_path")

class FastPath:
    def __init__(self):
        # Known safe technical queries to reduce false positives
        self.allowlist_patterns = [
            r"explain the laws of thermodynamics",
            r"how does photosynthesis work",
            r"quantum mechanics basics",
            r"python list comprehension examples",
            r"what is a decorator in python",
            r"how to use git merge",
            r"hi there!?",
            r"hello!?",
            r"ping"
        ]
        self.allowlist_regex = [re.compile(p, re.IGNORECASE) for p in self.allowlist_patterns]

    def is_known_safe(self, prompt: str) -> bool:
        """Check if a prompt matches a known safe pattern."""
        for pattern in self.allowlist_regex:
            if pattern.search(prompt):
                logger.info(f"Fast-Path: Known safe pattern matched. Skipping AI check.")
                return True
        return False

    def is_known_malicious(self, prompt: str) -> bool:
        """
        Optional: Can add additional high-speed regex here 
        if not already handled by input_filter.
        """
        return False
