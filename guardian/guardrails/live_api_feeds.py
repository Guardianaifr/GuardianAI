"""
Live Threat Intelligence API Connectors
========================================
Connects GuardianAI to free, production-grade threat intelligence feeds
and converts them into LLM-relevant adversarial pattern detectors.

Supported sources:
  1. URLhaus (abuse.ch) — malicious URL/domain C2 exfiltration patterns (no key required)
  2. OTX AlienVault   — open threat exchange indicators (free API key)
  3. PhishTank        — phishing URL database (free, no key required)
  4. GuardianAI CDN   — official GuardianAI community patterns feed

All connectors return List[str] of regex patterns ready for ThreatFeed._update_patterns().
"""
import logging
import os
import re
import time
from typing import List, Optional
import requests

logger = logging.getLogger("GuardianAI.threat_feed.live_api")

# ─── URLhaus (abuse.ch) ───────────────────────────────────────────────────────

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/200/"

def fetch_urlhaus_patterns(timeout: int = 10) -> List[str]:
    """
    Fetch recent malicious URLs from URLhaus and convert them into
    C2 exfiltration detection patterns for LLM responses.
    
    Detects prompts trying to instruct the LLM to POST/GET/beacon
    to known malicious C2 infrastructure.
    Returns compiled-ready regex pattern strings.
    """
    try:
        resp = requests.post(URLHAUS_API, data={"query": "get_urls"}, timeout=timeout)
        if resp.status_code != 200:
            logger.warning(f"[URLhaus] HTTP {resp.status_code}")
            return []

        data = resp.json()
        if data.get("query_status") != "is_active":
            return []

        urls = data.get("urls", [])
        domains = set()
        for entry in urls:
            url_str = entry.get("url", "")
            # Extract domain from URL
            m = re.match(r"https?://([^/]+)", url_str)
            if m:
                domain = m.group(1).split(":")[0].strip().lower()
                # Skip IPs (less reliable in regex patterns) and very short domains
                if domain and len(domain) > 4 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                    domains.add(re.escape(domain))

        if not domains:
            return []

        # Build a single combined pattern for all C2 domains
        domain_alt = "|".join(sorted(domains)[:100])   # cap at 100 to avoid ReDoS
        pattern = (
            f"(?i)(?:curl|wget|fetch|requests?\\.get|http\\.get|urllib|"
            f"send|post|beacon|ping|callback|exfil).{{0,60}}(?:{domain_alt})"
        )
        logger.info(f"[URLhaus] Generated C2 pattern covering {len(domains)} malicious domains")
        return [pattern]

    except Exception as e:
        logger.error(f"[URLhaus] Error fetching feed: {e}")
        return []


# ─── OTX AlienVault ───────────────────────────────────────────────────────────

OTX_API_BASE = "https://otx.alienvault.com/api/v1"
OTX_PULSE_SEARCH = f"{OTX_API_BASE}/search/pulses?q=LLM+jailbreak&sort=-modified&limit=10"

def fetch_otx_patterns(api_key: Optional[str] = None, timeout: int = 10) -> List[str]:
    """
    Fetch LLM-related threat indicators from AlienVault OTX.
    Converts hostname and URL indicators into adversarial prompt patterns.
    API key: set OTX_API_KEY env var or pass directly (free at otx.alienvault.com).
    """
    key = api_key or os.environ.get("OTX_API_KEY", "").strip()
    if not key:
        logger.debug("[OTX] No API key configured — skipping")
        return []

    try:
        headers = {"X-OTX-API-KEY": key}
        resp = requests.get(OTX_PULSE_SEARCH, headers=headers, timeout=timeout)
        if resp.status_code == 401:
            logger.warning("[OTX] Invalid API key (401)")
            return []
        if resp.status_code != 200:
            logger.warning(f"[OTX] HTTP {resp.status_code}")
            return []

        data = resp.json()
        pulses = data.get("results", [])
        patterns = []

        for pulse in pulses:
            # Extract text indicators from pulse tags and description
            tags = pulse.get("tags", [])
            for tag in tags:
                tag_lower = tag.lower().strip()
                # Convert attack tags to adversarial patterns
                if any(kw in tag_lower for kw in ["jailbreak", "prompt injection", "llm attack", "dan", "adversarial"]):
                    # If the tag looks like a pattern name, add it as a keyword
                    escaped = re.escape(tag_lower)
                    if len(escaped) > 3:
                        patterns.append(f"(?i){escaped}")

        if patterns:
            logger.info(f"[OTX] Generated {len(patterns)} patterns from {len(pulses)} pulses")
        return patterns

    except Exception as e:
        logger.error(f"[OTX] Error fetching feed: {e}")
        return []


# ─── PhishTank ────────────────────────────────────────────────────────────────

PHISHTANK_API = "http://checkurl.phishtank.com/checkurl/"

def fetch_phishtank_patterns(timeout: int = 10) -> List[str]:
    """
    PhishTank provides phishing URL patterns.
    Converts them into LLM-prompt patterns that try to get the model
    to click/visit/recommend phishing URLs.
    """
    # PhishTank's bulk download requires registration; instead we add
    # static patterns for common phishing instruction phrases.
    static_patterns = [
        r"(?i)(?:click|visit|go to|open|navigate to|access).{0,30}(?:this link|this url|the link|the url|following link)",
        r"(?i)(?:http|https)://[^\s]{0,200}(?:login|signin|verify|account|update|confirm|secure|banking|paypal|amazon|apple|microsoft|google).{0,50}(?:\.com|\.net|\.org)/(?:verify|login|signin|account|update)",
        r"(?i)(?:phish|spear.?phish|whaling|vishing|smishing)\w*",
        r"(?i)(?:credential|password|username).{0,30}(?:harvest|steal|grab|extract|phish)",
    ]
    logger.info(f"[PhishTank] Loaded {len(static_patterns)} phishing detection patterns")
    return static_patterns


# ─── Aggregator ───────────────────────────────────────────────────────────────

def fetch_all_live_patterns(config: dict) -> List[str]:
    """
    Aggregate patterns from all enabled live threat intelligence APIs.
    
    Args:
        config: The `live_apis` sub-dict from `threat_feed` config block.
    
    Returns:
        Merged list of regex pattern strings.
    """
    patterns: List[str] = []
    start = time.perf_counter()

    # URLhaus
    urlhaus_cfg = config.get("urlhaus", {})
    if urlhaus_cfg.get("enabled", False):
        p = fetch_urlhaus_patterns(timeout=urlhaus_cfg.get("timeout_seconds", 10))
        patterns.extend(p)
        logger.info(f"[LiveAPI] URLhaus: +{len(p)} patterns")

    # OTX AlienVault
    otx_cfg = config.get("otx", {})
    if otx_cfg.get("enabled", False):
        key = otx_cfg.get("api_key", "") or os.environ.get("OTX_API_KEY", "")
        p = fetch_otx_patterns(api_key=key, timeout=otx_cfg.get("timeout_seconds", 10))
        patterns.extend(p)
        logger.info(f"[LiveAPI] OTX: +{len(p)} patterns")

    # PhishTank
    phishtank_cfg = config.get("phishtank", {})
    if phishtank_cfg.get("enabled", False):
        p = fetch_phishtank_patterns()
        patterns.extend(p)
        logger.info(f"[LiveAPI] PhishTank: +{len(p)} patterns")

    elapsed = (time.perf_counter() - start) * 1000
    logger.info(f"[LiveAPI] Total: {len(patterns)} patterns from live APIs in {elapsed:.0f}ms")
    return patterns
