"""
Exfiltration Scanner — 2026 Standard Data Exfiltration Detection.

Detects patterns in AI-generated code that would enable data exfiltration:
  - Environment variable harvesting (os.environ, process.env)
  - DNS tunneling (encoded subdomain exfiltration)
  - HTTP exfiltration (POST with base64/hex encoded data)
  - File system credential scanning (~/.ssh, ~/.aws, .env)
  - Clipboard monitoring and keylogging patterns

2026 Standard: MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol
"""

from __future__ import annotations

import logging
import re
from typing import List, Tuple

logger = logging.getLogger("guardian.audit.remediation.exfiltration")


class ExfiltrationScanner:
    """
    Detects data exfiltration patterns in AI-generated code.

    Usage:
        scanner = ExfiltrationScanner()
        found, reason = scanner.scan_output(code_output)
    """

    # ── Input patterns: requests to generate exfiltration tools ──────────
    INPUT_EXFIL_PATTERNS: List[Tuple[str, str]] = [
        (r"(?:exfiltrate|steal|extract|harvest|dump|scrape)\s+(?:all\s+)?(?:environment|env)\s+(?:variables?|vars?)", "Environment variable exfiltration request"),
        (r"(?:exfiltrate|steal|send|transmit)\s+(?:data|secrets?|keys?|credentials?)\s+(?:via|over|through|using)\s+(?:DNS|ICMP|NTP)", "Covert channel exfiltration request"),
        (r"(?:stolen?|exfiltrat\w+)\s+(?:\w+\s+){0,3}(?:via|over|through|using)\s+(?:DNS|ICMP|NTP)\s+(?:tunnel|channel|exfil)", "Covert channel exfiltration (alt phrasing)"),
        (r"(?:DNS|ICMP|NTP)\s+tunnel", "DNS/ICMP tunneling reference"),
        (r"(?:scan|search|find|locate|harvest)\s+(?:for\s+)?(?:private\s+keys?|credentials?|secrets?|passwords?)\s+(?:on|in|across)\s+(?:the\s+)?(?:server|system|disk|filesystem|machine)", "Server-side credential scanning request"),
        (r"(?:scan|search|find|locate|harvest)\s+(?:the\s+)?(?:server|system|disk|filesystem|machine|directory|folder)\s+(?:for\s+)?(?:private\s+keys?|credentials?|secrets?|passwords?|AWS)", "Credential filesystem scan (alt phrasing)"),
        (r"(?:silently|covertly|stealthily|quietly)\s+(?:send|transmit|upload|exfiltrate|transfer)", "Stealth data exfiltration request"),
        (r"(?:keylog|key\s*log|keyboard\s+capture|keystroke\s+log)", "Keylogging request"),
        (r"(?:clipboard\s+(?:monitor|capture|sniff|steal|intercept))", "Clipboard monitoring request"),
        (r"(?:C2|C&C|command.and.control)\s+server", "C2 server reference"),
    ]

    # ── Output patterns: generated exfiltration code ─────────────────────
    OUTPUT_EXFIL_PATTERNS: List[Tuple[str, str, str]] = [
        # Environment variable harvesting
        (
            r"(?:os\.environ|os\.getenv|process\.env)\s*(?:\[|\.(?:get|items|keys|values))",
            "Environment variable access pattern",
            "HIGH",
        ),
        (
            r"for\s+\w+\s*,?\s*\w*\s+in\s+os\.environ\.items\(\)",
            "Environment variable enumeration loop",
            "CRITICAL",
        ),
        (
            r"json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ",
            "Environment variable serialization for exfiltration",
            "CRITICAL",
        ),

        # DNS tunneling
        (
            r"(?:socket\.(?:gethostbyname|getaddrinfo)|dns\.resolver\.resolve|dnslib)",
            "DNS resolution/tunneling library usage",
            "MEDIUM",
        ),
        (
            r"(?:base64|hex)[\s\S]{0,50}\.encode[\s\S]{0,100}(?:\.(?:com|net|org|io)|subdomain|dns)",
            "Encoded subdomain DNS tunneling pattern",
            "CRITICAL",
        ),
        (
            r"(?:subprocess|os\.system|os\.popen)[\s\S]{0,100}(?:nslookup|dig|host)\s+",
            "DNS query-based exfiltration",
            "HIGH",
        ),

        # HTTP exfiltration
        (
            r"requests\.(?:post|put)\s*\(\s*['\"]https?://[\s\S]{0,200}(?:base64|encode|hex|json\.dumps)",
            "HTTP POST exfiltration with encoding",
            "CRITICAL",
        ),
        (
            r"urllib\.request\.urlopen[\s\S]{0,200}(?:base64|encode|hex)",
            "urllib exfiltration with encoding",
            "HIGH",
        ),
        (
            r"(?:webhook|pastebin|requestbin|ngrok|burpcollaborator|interact\.sh)",
            "Known exfiltration endpoint usage",
            "CRITICAL",
        ),

        # File system credential scanning
        (
            r"(?:glob|os\.walk|os\.listdir|pathlib)[\s\S]{0,200}(?:\.ssh|\.aws|\.gnupg|\.config|\.env|id_rsa|credentials|\.npmrc|\.pypirc)",
            "Credential file system scanning",
            "CRITICAL",
        ),
        (
            r"open\s*\(\s*(?:os\.path\.(?:expanduser|join)|Path)[\s\S]{0,100}(?:\.ssh|id_rsa|\.aws|credentials|\.env|\.git-credentials|\.netrc)",
            "Credential file reading pattern",
            "CRITICAL",
        ),
        (
            r"(?:~\/|/home/|/root/|C:\\\\Users)[\s\S]{0,50}(?:\.ssh|\.aws|\.gnupg|\.env|\.git-credentials)",
            "Hardcoded credential path access",
            "HIGH",
        ),

        # Process/memory dumping
        (
            r"(?:\/proc\/\d+\/(?:maps|mem|environ|cmdline)|/proc/self/environ)",
            "Linux /proc memory/environ access",
            "CRITICAL",
        ),
        (
            r"ctypes[\s\S]{0,200}(?:ReadProcessMemory|OpenProcess|VirtualQueryEx)",
            "Windows process memory reading",
            "CRITICAL",
        ),

        # Clipboard/keylogging
        (
            r"(?:pynput|keyboard|pyHook)[\s\S]{0,200}(?:on_press|listener|hook|log)",
            "Keylogging library usage",
            "CRITICAL",
        ),
        (
            r"(?:pyperclip|clipboard|win32clipboard|tkinter\.clipboard)[\s\S]{0,200}(?:paste|get|read|monitor|loop|while)",
            "Clipboard monitoring pattern",
            "HIGH",
        ),

        # Screen capture
        (
            r"(?:pyautogui|PIL|mss|ImageGrab)[\s\S]{0,200}(?:screenshot|grab|capture)[\s\S]{0,100}(?:save|send|post|upload|write)",
            "Screen capture and exfiltration",
            "HIGH",
        ),

        # Network reconnaissance
        (
            r"(?:socket\.socket|nmap|scapy)[\s\S]{0,200}(?:connect|scan|SYN|ping)[\s\S]{0,100}(?:range|for\s+\w+\s+in)",
            "Network port scanning pattern",
            "MEDIUM",
        ),
    ]

    def __init__(self):
        self._input_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in self.INPUT_EXFIL_PATTERNS
        ]
        self._output_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc, severity)
            for p, desc, severity in self.OUTPUT_EXFIL_PATTERNS
        ]

    def check_input(self, user_message: str) -> Tuple[bool, str]:
        """Check if a user request is attempting to generate exfiltration tools."""
        for pattern, description in self._input_patterns:
            if pattern.search(user_message):
                return True, f"Exfiltration request blocked: {description}"
        return False, ""

    def scan_output(self, response: str) -> Tuple[bool, str]:
        """Scan AI output for exfiltration code patterns."""
        for pattern, description, severity in self._output_patterns:
            if pattern.search(response):
                logger.warning(f"Exfiltration detected [{severity}]: {description}")
                return True, f"[{severity}] {description}"
        return False, ""

    def scan_all(self, response: str) -> List[Tuple[str, str]]:
        """Return all exfiltration matches found."""
        findings = []
        for pattern, description, severity in self._output_patterns:
            if pattern.search(response):
                findings.append((severity, description))
        return findings

    def is_safe(self, user_message: str, response: str) -> Tuple[bool, str]:
        """Combined input + output check. Returns (is_safe, reason_if_blocked)."""
        blocked, reason = self.check_input(user_message)
        if blocked:
            return False, f"INPUT: {reason}"
        blocked, reason = self.scan_output(response)
        if blocked:
            return False, f"OUTPUT: {reason}"
        return True, ""
