"""
Web3 Domain Intelligence & Phishing URL Defense Engine

Provides fast domain extraction and threat intelligence for prompt-embedded Web3 URLs.
Detects:
  - Known malicious Web3 phishing domains / wallet drainers
  - Brand typosquatting and impersonation (e.g. polymarket.mx, soniclabs.info, ogntoken-migration.icu)
  - High-risk crypto TLD combos (.icu, .top, .click, etc. combined with airdrop/migration/claim keywords)
  - Integration with local blocklist cache and MetaMask phishing list format
Allows legitimate Web3 brands without false positives (etherscan.io, metamask.io, opensea.io, cryptokitties.co, etc.)
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("GuardianAI.domain_intel")


@dataclass
class DomainThreatResult:
    """Evaluation result for prompt-embedded domains and URLs."""
    is_phishing: bool
    risk_score: float                  # 0.0 (safe) to 1.0 (dangerous)
    flagged_domains: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    extracted_domains: List[str] = field(default_factory=list)
    legitimate_domains: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Allowlist: Legitimate Web3 Brands & Infrastructure (Zero False Positives)
# Subdomains of any allowed domain are automatically allowed.
# ---------------------------------------------------------------------------
DEFAULT_LEGITIMATE_DOMAINS: Set[str] = {
    # Core Ethereum & L1/L2
    "ethereum.org",
    "etherscan.io",
    "metamask.io",
    "opensea.io",
    "cryptokitties.co",
    "uniswap.org",
    "uniswap.com",
    "pancakeswap.finance",
    "sushi.com",
    "sushiswap.com",
    "curve.fi",
    "aave.com",
    "compound.finance",
    "makerdao.com",
    "balancer.fi",
    "polygon.technology",
    "arbitrum.io",
    "optimism.io",
    "base.org",
    "solana.com",
    "avalanche.org",
    "avax.network",
    "monad.xyz",
    "polymarket.com",          # Official Polymarket
    "soniclabs.com",           # Official Sonic Labs
    "originprotocol.com",      # Official Origin Protocol (OGN)
    "ogn.org",
    "coingecko.com",
    "coinmarketcap.com",
    "defillama.com",
    "dune.com",
    "chainlist.org",
    "infura.io",
    "alchemy.com",
    "quicknode.com",
    "tenderly.co",
    "ledger.com",
    "trezor.io",
    "walletconnect.com",
    "walletconnect.org",
    "gitcoin.co",
    "snapshot.org",
    "ens.domains",
    "blur.io",
    "revoke.cash",
    "safe.global",
    "gnosis.io",
    "eigenlayer.xyz",
    "binance.com",
    "coinbase.com",
    "kraken.com",
    "okx.com",
    "bybit.com",
    "bitget.com",
    "gemini.com",
    "deribit.com",

    # Core Developer & Information Platforms
    "github.com",
    "gitlab.com",
    "google.com",
    "twitter.com",
    "x.com",
    "discord.com",
    "discord.gg",
    "telegram.org",
    "t.me",
    "medium.com",
    "wikipedia.org",
    "arxiv.org",
    "huggingface.co",
    "reddit.com",
    "youtube.com",
    "example.com",
    "example.org",
    "localhost",
}

# ---------------------------------------------------------------------------
# Default Seed Blocklist: Known Phishing / Wallet Drainer / Scam Domains
# ---------------------------------------------------------------------------
DEFAULT_PHISHING_BLOCKLIST: Set[str] = {
    # Empirical audit targets
    "ogntoken-migration.icu",
    "polymarket.mx",
    "soniclabs.info",
    "unisvvap.com",
    "pancakesvvap.com",
    "app-uniswap.xyz",
    "app-uniswap.site",
    "app-uniswap.click",
    "app-uniswap.top",
    "uniswap-airdrop.claim",
    "claim-uniswap.org.ru",
    "metamask-connect.xyz",
    "metamusk.io",
    "metamask-verify.online",
    "metamask-auth.com",
    "metamask-rectify.com",
    "opensea-claim.site",
    "opensea-mint.xyz",
    "opensea-free.site",
    "cryptokitties.top",
    "cryptokitties-claim.xyz",
    "blur-airdrop.top",
    "arbitrum-airdrop.claims",
    "curve-fi.exchange",
    "curv-fi.com",
    "wallet-rectify.xyz",
    "wallet-sync.click",
    "collab-land-portal.click",
    "drainer-portal.site",
    "revoke-approval-cash.xyz",
    "eigenlayer-claims.xyz",
    "monad-airdrop.site",
}

# ---------------------------------------------------------------------------
# Protected Brand Mapping for Typosquatting / Impersonation Detection
# Maps brand identifier -> official legitimate domain
# ---------------------------------------------------------------------------
PROTECTED_BRANDS: Dict[str, str] = {
    "polymarket": "polymarket.com",
    "soniclabs": "soniclabs.com",
    "ogntoken": "originprotocol.com",
    "originprotocol": "originprotocol.com",
    "etherscan": "etherscan.io",
    "metamask": "metamask.io",
    "opensea": "opensea.io",
    "cryptokitties": "cryptokitties.co",
    "uniswap": "uniswap.org",
    "pancakeswap": "pancakeswap.finance",
    "sushiswap": "sushi.com",
    "curvefi": "curve.fi",
    "walletconnect": "walletconnect.com",
    "ledger": "ledger.com",
    "trezor": "trezor.io",
    "arbitrum": "arbitrum.io",
    "optimism": "optimism.io",
    "revoke": "revoke.cash",
}

# ---------------------------------------------------------------------------
# High-Risk Scam TLDs and Phishing Keywords
# ---------------------------------------------------------------------------
HIGH_RISK_TLDS: Set[str] = {
    "icu", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "rest",
    "click", "surf", "monster", "quest", "sbs", "cfd", "link",
    "live", "cloud", "work", "loan", "party", "racing", "review",
}

CRYPTO_PHISHING_KEYWORDS: Set[str] = {
    "token", "migration", "migrate", "airdrop", "claim", "presale",
    "connect", "wallet", "sync", "rectify", "auth", "dao", "vault",
    "staking", "reward", "rewards", "drain", "swap", "dex", "sonic",
    "ogn", "drop", "bonus", "mint", "verify", "update",
}

# Obfuscated URL Shorteners commonly abused in crypto scams
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "goo.gl", "rb.gy", "shorturl.at", "tiny.cc", "bc.vc",
}

# Confusable IDN homoglyph translation map (Cyrillic, Greek, Latin lookalikes -> ASCII)
HOMOGLYPH_MAP = str.maketrans({
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
    '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0501': 'd', '\u051b': 'q', '\u051d': 'w',
    '\u03bf': 'o', '\u03c1': 'p', '\u03c5': 'u', '\u03bd': 'v', '\u03ba': 'k', '\u03c4': 't',
    '\u0142': 'l', '\u0131': 'i',
})



class Web3DomainIntel:
    """
    Fast Web3 URL / domain extractor and threat intelligence classifier.
    
    Provides deterministic defense against prompt-embedded phishing dApps,
    typosquatting clones, and wallet drainers with sub-millisecond execution.
    """

    def __init__(self, cache_file: Optional[str] = None):
        self.legitimate_domains = set(DEFAULT_LEGITIMATE_DOMAINS)
        self.blocked_domains = set(DEFAULT_PHISHING_BLOCKLIST)
        self.protected_brands = dict(PROTECTED_BRANDS)
        self.cache_file = cache_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data",
            "phishing_blocklist.json",
        )
        self._load_cache()

        # Regex for URLs and potential domains
        # Handles http://, https://, hxxps://, ftp:// and naked domain.tld
        self._url_pattern = re.compile(
            r"(?:https?|hxxps?|ftp)://[^\s/$.?#].[^\s]*",
            re.IGNORECASE,
        )
        # Match naked domains: e.g. ogntoken-migration.icu, polymarket.mx
        self._domain_pattern = re.compile(
            r"(?:\b|(?<=[\s/]))(?:[\w](?:[\w-]{0,61}[\w])?\.)+[\w]{2,63}(?:\b|(?=[\s/]))",
            re.UNICODE,
        )
        # Typosquatting / Leetspeak specific brand patterns
        self._brand_typo_patterns = [
            (re.compile(r"unisv+ap", re.IGNORECASE), "uniswap"),
            (re.compile(r"pancakesv+ap", re.IGNORECASE), "pancakeswap"),
            (re.compile(r"metamusk", re.IGNORECASE), "metamask"),
            (re.compile(r"ether-?scan", re.IGNORECASE), "etherscan"),
            (re.compile(r"curv-?fi", re.IGNORECASE), "curvefi"),
            (re.compile(r"open-?sea", re.IGNORECASE), "opensea"),
            (re.compile(r"crypto-?kitties", re.IGNORECASE), "cryptokitties"),
            (re.compile(r"sonic-?labs", re.IGNORECASE), "soniclabs"),
            (re.compile(r"poly-?market", re.IGNORECASE), "polymarket"),
            (re.compile(r"ogn-?token", re.IGNORECASE), "ogntoken"),
        ]

    def _load_cache(self) -> None:
        """Loads additional blocked domains from local cache file or MetaMask format."""
        if not self.cache_file or not os.path.exists(self.cache_file):
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for d in data:
                        cleaned = self.normalize_domain(str(d))
                        if cleaned:
                            self.blocked_domains.add(cleaned)
                elif isinstance(data, dict):
                    # MetaMask phishing-detect format
                    for b in data.get("blacklist", []):
                        cleaned = self.normalize_domain(str(b))
                        if cleaned:
                            self.blocked_domains.add(cleaned)
                    for w in data.get("whitelist", []):
                        cleaned = self.normalize_domain(str(w))
                        if cleaned:
                            self.legitimate_domains.add(cleaned)
            logger.info(f"Loaded {len(self.blocked_domains)} blocked domains into threat cache.")
        except Exception as e:
            logger.warning(f"Could not load domain cache from {self.cache_file}: {e}")

    def save_cache(self) -> None:
        """Persists currently blocked domains to the local cache file."""
        if not self.cache_file:
            return
        try:
            dir_name = os.path.dirname(self.cache_file)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(sorted(list(self.blocked_domains)), f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save domain cache: {e}")

    @staticmethod
    def defang_text(text: str) -> str:
        """De-fangs common obfuscated domain/URL conventions in text."""
        if not text:
            return ""
        cleaned = re.sub(
            r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|\[d0t\]|\(d0t\)|\{dot\}",
            ".",
            text,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(r"\[:\]//|\[://\]", "://", cleaned)
        cleaned = re.sub(r"\bhttp\[s\]://", "https://", cleaned, flags=re.IGNORECASE)
        return cleaned

    @staticmethod
    def deconfuse(domain: str) -> str:
        """Decodes Punycode and normalizes confusable unicode homoglyphs to ASCII equivalents."""
        if not domain:
            return ""
        d = domain
        try:
            if "xn--" in d:
                parts = [
                    p.encode("ascii").decode("idna") if p.startswith("xn--") else p
                    for p in d.split(".")
                ]
                d = ".".join(parts)
        except Exception:
            pass
        import unicodedata
        d = unicodedata.normalize("NFKC", d)
        d = "".join(c for c in unicodedata.normalize("NFD", d) if unicodedata.category(c) != "Mn")
        return d.translate(HOMOGLYPH_MAP).lower()

    @classmethod
    def normalize_domain(cls, target: str) -> str:
        """
        Extracts and normalizes the host/domain name from a URL or raw domain string.
        Strips schemes, paths, query parameters, ports, defanging, and trailing punctuation.
        """
        if not target:
            return ""
        cleaned = cls.defang_text(target)
        cleaned = re.sub(r"hxxps?://", "https://", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.strip().strip("\"'<>[](){}:;,")

        # Parse with urllib if it looks like a URL
        if "://" in cleaned:
            try:
                parsed = urlparse(cleaned)
                host = parsed.hostname or ""
            except Exception:
                host = cleaned.split("://", 1)[-1].split("/")[0]
        else:
            # Take the first path segment
            host = cleaned.split("/")[0].split("?")[0].split("#")[0]

        # Strip userinfo (user:pass@host) or port (:8080)
        if "@" in host:
            host = host.split("@")[-1]
        if ":" in host:
            host = host.split(":")[0]

        return host.strip().strip(".").lower()

    def extract_urls(self, text: str) -> List[str]:
        """Extracts all full URL strings from text (including defanged URLs)."""
        if not text:
            return []
        defanged = self.defang_text(text)
        matches = self._url_pattern.findall(defanged)
        return [m.strip().strip("\"'<>[](){}:;,") for m in matches if m]


    def extract_domains(self, text: str) -> List[str]:
        """
        Extracts all candidate domain names from text (both inside URLs and bare domains).
        Handles defanged domains, naked hostnames, and Unicode/IDN domains.
        Filters out common false positives like file extensions or version strings.
        """
        if not text:
            return []
        found_domains: Set[str] = set()

        # 1. Extract from full URLs first
        for url in self.extract_urls(text):
            norm = self.normalize_domain(url)
            if norm and "." in norm:
                found_domains.add(norm)

        # 2. Extract naked domains from text and defanged text
        for variant in (text, self.defang_text(text)):
            for match in self._domain_pattern.finditer(variant):
                candidate = match.group(0)
                norm = self.normalize_domain(candidate)
                if not norm or "." not in norm:
                    continue
                tld = norm.split(".")[-1]
                # Discard non-domains (e.g. numeric versions, single letter) unless IPv4
                if tld.isdigit():
                    # Keep valid IPv4
                    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", norm):
                        continue
                elif len(tld) < 2:
                    continue
                # Discard common code extensions unless preceded by dot and valid brand
                if tld in {"py", "js", "ts", "json", "yaml", "yml", "html", "css", "md", "txt", "log", "lock", "db"}:
                    continue
                found_domains.add(norm)

        return sorted(list(found_domains))

    def is_legitimate(self, domain: str) -> bool:
        """
        Checks if a domain belongs to the legitimate allowlist.
        Exact match or valid subdomain of an allowlisted domain returns True.
        """
        d = domain.lower()
        if d in self.legitimate_domains:
            return True
        for legit in self.legitimate_domains:
            if d.endswith("." + legit):
                return True
        return False

    def evaluate_domain(self, domain: str, prompt_context: str = "") -> Tuple[bool, float, str]:
        """
        Evaluates a single domain for phishing or malicious characteristics.
        
        Returns:
            (is_phishing, risk_score, reason)
        """
        domain_norm = self.normalize_domain(domain)
        if not domain_norm:
            return False, 0.0, "Empty domain"

        # 1. Allowlist check — immediate safe exit
        if self.is_legitimate(domain_norm):
            return False, 0.0, f"Legitimate verified domain: {domain_norm}"

        parts = domain_norm.split(".")
        tld = parts[-1]
        sld = parts[-2] if len(parts) >= 2 else ""

        # 2. Match against blocked list / local cache (including all subdomains)
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True, 1.0, f"Domain matches known malicious blocklist: {domain_norm} (blocked base: {parent})"

        # 3. IDN Homoglyph / Punycode Impersonation Check
        domain_deconfused = self.deconfuse(domain_norm)
        if domain_deconfused != domain_norm:
            # Check if the deconfused form spoofs an allowlisted domain or protected brand
            if self.is_legitimate(domain_deconfused):
                return (
                    True,
                    0.99,
                    f"Homoglyph/Punycode spoofing legitimate domain '{domain_deconfused}' detected: {domain_norm}",
                )
            for brand, official_domain in self.protected_brands.items():
                if brand in domain_deconfused:
                    return (
                        True,
                        0.99,
                        f"Homoglyph/Punycode brand impersonation targeting '{official_domain}' detected: {domain_norm}",
                    )

        # 4. Check for Typosquatting / Leetspeak Brand Clones
        for domain_variant in (domain_norm, domain_deconfused):
            for typo_re, official_brand_key in self._brand_typo_patterns:
                if typo_re.search(domain_variant):
                    official_domain = self.protected_brands.get(official_brand_key, "")
                    if domain_norm != official_domain and not domain_norm.endswith("." + official_domain):
                        return (
                            True,
                            0.98,
                            f"Typosquatting clone of brand '{official_brand_key}' detected: {domain_norm} (official: {official_domain})",
                        )

        # 5. Brand Impersonation / Fake TLD Spoofing
        # E.g. polymarket.mx vs polymarket.com, soniclabs.info vs soniclabs.com
        for domain_variant in (domain_norm, domain_deconfused):
            for brand, official_domain in self.protected_brands.items():
                # Check for brand token or exact SLD match to prevent false positives on partial substrings
                brand_match = False
                if brand in domain_variant:
                    if re.search(rf"(?:^|[\.-]){re.escape(brand)}(?:[\.-]|$)", domain_variant):
                        brand_match = True
                    elif sld == brand:
                        brand_match = True
                if brand_match:
                    if domain_norm != official_domain and not domain_norm.endswith("." + official_domain):
                        return (
                            True,
                            0.95,
                            f"Brand impersonation targeting '{official_domain}' detected: {domain_norm}",
                        )

        # 6. High-Risk TLD + Crypto Phishing Keywords
        # E.g. ogntoken-migration.icu, claim-airdrop.top, wallet-sync.click
        if tld in HIGH_RISK_TLDS:
            for kw in CRYPTO_PHISHING_KEYWORDS:
                if kw in domain_norm or kw in domain_deconfused:
                    return (
                        True,
                        0.90,
                        f"High-risk phishing pattern (TLD .{tld} + keyword '{kw}') detected: {domain_norm}",
                    )

        # 7. URL Shorteners in Web3 Context
        if domain_norm in URL_SHORTENERS:
            if prompt_context:
                ctx_low = prompt_context.lower()
                if any(kw in ctx_low for kw in CRYPTO_PHISHING_KEYWORDS):
                    return (
                        True,
                        0.88,
                        f"Obfuscated URL shortener used in Web3/crypto context: {domain_norm}",
                    )

        # 8. Direct Raw IP Address as Web3 Target (excluding localhost/loopback)
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain_norm):
            if domain_norm not in {"127.0.0.1", "0.0.0.0"}:
                if prompt_context:
                    ctx_low = prompt_context.lower()
                    if any(kw in ctx_low for kw in CRYPTO_PHISHING_KEYWORDS):
                        return (
                            True,
                            0.92,
                            f"Direct IP address used as Web3 dApp destination: {domain_norm}",
                        )

        # 9. Combined Context Heuristics: Action Trap in Prompt + Non-Allowlisted Domain
        # If the user prompt specifically instructs wallet connection, airdrop claim,
        # or token migration to an unverified external domain, treat as critical threat.
        if prompt_context:
            context_lower = prompt_context.lower()
            urgent_actions = [
                "claim your airdrop", "connect your wallet", "connect wallet",
                "claim airdrop", "migrate your tokens", "token migration",
                "sync your wallet", "rectify wallet", "claim tokens",
                "whitelist your address", "approve contract to continue",
            ]
            if any(act in context_lower for act in urgent_actions):
                # Has a crypto keyword in the domain, URL, or context
                if any(kw in domain_norm for kw in CRYPTO_PHISHING_KEYWORDS) or any(kw in context_lower for kw in CRYPTO_PHISHING_KEYWORDS):
                    return (
                        True,
                        0.88,
                        f"Action-trap phishing dApp targeting unverified domain: {domain_norm}",
                    )

        return False, 0.0, f"Domain clean: {domain_norm}"


    def evaluate(self, text: str) -> DomainThreatResult:
        """
        Evaluates full prompt text for any embedded phishing URLs or domains.
        """
        if not text:
            return DomainThreatResult(
                is_phishing=False,
                risk_score=0.0,
                flagged_domains=[],
                reasons=[],
                extracted_domains=[],
                legitimate_domains=[],
            )

        extracted = self.extract_domains(text)
        flagged: List[str] = []
        reasons: List[str] = []
        legit: List[str] = []
        max_risk = 0.0

        for domain in extracted:
            is_phish, risk, reason = self.evaluate_domain(domain, prompt_context=text)
            if is_phish:
                flagged.append(domain)
                reasons.append(reason)
                max_risk = max(max_risk, risk)
            elif self.is_legitimate(domain):
                legit.append(domain)

        return DomainThreatResult(
            is_phishing=bool(flagged),
            risk_score=max_risk,
            flagged_domains=flagged,
            reasons=reasons,
            extracted_domains=extracted,
            legitimate_domains=legit,
        )

    def check_prompt(self, prompt: str) -> bool:
        """
        Fast Boolean check compatible with guardrail interfaces.
        Returns True if prompt is safe (no phishing URLs), False if blocked.
        """
        res = self.evaluate(prompt)
        return not res.is_phishing

    def add_blocked_domain(self, domain: str) -> None:
        """Dynamically add a domain to the in-memory and persisted blocklist."""
        norm = self.normalize_domain(domain)
        if norm:
            self.blocked_domains.add(norm)
            self.save_cache()

    def remove_blocked_domain(self, domain: str) -> None:
        """Remove a domain from the blocklist."""
        norm = self.normalize_domain(domain)
        if norm in self.blocked_domains:
            self.blocked_domains.remove(norm)
            self.save_cache()
