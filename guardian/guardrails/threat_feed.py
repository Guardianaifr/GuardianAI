"""
ThreatFeed — Enterprise-Grade Threat Intelligence Engine

Advanced capabilities (this version):
1. HMAC-SHA256 feed signature verification (X-Feed-Signature header)
2. Pattern severity tagging (critical/high/medium/low) via extended YAML schema
3. Admin API: add_pattern(), remove_pattern(), dump_patterns(), refresh_now()
4. Pattern TTL: auto-expire patterns after configurable number of days
5. Brain auto-patch: add_pattern() accepts hot-patches from CyberBrain

Plus existing:
- Remote YAML feeds with Bearer token auth
- Local YAML fallback
- Multi-source merging with deduplication
- SHA-256 change detection
- Circuit breaker per URL
- Thread-timeout ReDoS sandbox
- Per-pattern match count metrics
- Prometheus-compatible status endpoint
- URLhaus / OTX / PhishTank live API connectors
- SSRF redirect blocking
"""
import hashlib
import hmac
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import yaml

logger = logging.getLogger("GuardianAI.threat_feed")

def _re2_ignorecase():
    """Case-insensitive RE2 options. google-re2 has no re2.IGNORECASE flag; it takes an Options object."""
    import re2
    opts = re2.Options()
    opts.case_sensitive = False
    return opts

# Bundled fallback feed shipped with the package
_BUILTIN_FEED_PATH = (
    Path(__file__).parent.parent.parent
    / "artifacts"
    / "threat_feeds"
    / "community_threat_feed_v1.yaml"
)

# Severity levels (ordered highest → lowest)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
DEFAULT_SEVERITY = "medium"
DEFAULT_TTL_DAYS = 30


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class PatternEntry:
    """A single threat pattern with metadata."""
    pattern: str
    severity: str = DEFAULT_SEVERITY        # critical / high / medium / low
    category: str = "unknown"
    source: str = "bundled"
    added_at: float = field(default_factory=time.time)
    ttl_days: Optional[int] = None          # None = never expires
    compiled: Optional[re.Pattern] = field(default=None, repr=False)

    @property
    def is_expired(self) -> bool:
        if self.ttl_days is None:
            return False
        return (time.time() - self.added_at) > (self.ttl_days * 86400)


# ─── Circuit breaker ──────────────────────────────────────────────────────────

class CircuitBreaker:
    """Simple per-URL circuit breaker: open after max_failures, resets after cooldown."""

    def __init__(self, max_failures: int = 3, cooldown_seconds: int = 300):
        self.max_failures = max_failures
        self.cooldown_seconds = cooldown_seconds
        self._failures: Dict[str, int] = {}
        self._opened_at: Dict[str, float] = {}

    def is_open(self, url: str) -> bool:
        failures = self._failures.get(url, 0)
        if failures < self.max_failures:
            return False
        opened = self._opened_at.get(url, 0)
        if time.time() - opened >= self.cooldown_seconds:
            self._failures[url] = 0
            return False
        return True

    def record_failure(self, url: str):
        self._failures[url] = self._failures.get(url, 0) + 1
        if self._failures[url] >= self.max_failures:
            self._opened_at[url] = time.time()
            logger.warning(
                f"[ThreatFeed] Circuit breaker OPEN for {url} "
                f"after {self._failures[url]} failures. "
                f"Cooldown: {self.cooldown_seconds}s"
            )

    def record_success(self, url: str):
        self._failures.pop(url, None)
        self._opened_at.pop(url, None)


# ─── Main engine ──────────────────────────────────────────────────────────────

class ThreatFeed:
    """
    Enterprise-grade multi-source threat pattern feed.
    """

    THREAT_FEED_SCHEMA = {
        "type": "object",
        "properties": {
            "patterns": {"type": "array"},              # list of str OR dict
            "version": {"type": "string"},
            "description": {"type": "string"},
            "hmac_key_id": {"type": "string"},          # optional key ID for HMAC verification
        },
        "required": ["patterns"],
    }

    def __init__(
        self,
        feed_url: str = None,
        update_interval: int = 3600,
        additional_feeds: Optional[List[str]] = None,
        local_fallback: Optional[str] = None,
        api_key: Optional[str] = None,
        hmac_secret: Optional[str] = None,
        ed25519_pubkey: Optional[str] = None,
        circuit_breaker_max_failures: int = 3,
        circuit_breaker_cooldown: int = 300,
        live_apis_config: Optional[dict] = None,
        default_ttl_days: Optional[int] = None,
    ):
        # ── HTTPS-only enforcement ─────────────────────────────────────────
        if feed_url and not feed_url.lower().startswith("https://"):
            logger.warning(
                f"[ThreatFeed] Rejected feed_url '{feed_url}' — only HTTPS URLs are allowed."
            )
            feed_url = None

        self.feed_url = feed_url
        self.update_interval = update_interval
        self.additional_feeds = [
            u for u in (additional_feeds or []) if u.lower().startswith("https://")
        ]
        self.local_fallback = local_fallback or str(_BUILTIN_FEED_PATH)

        # ── Auth ───────────────────────────────────────────────────────────
        self.api_key = api_key or os.environ.get("GUARDIAN_THREAT_FEED_KEY", "").strip() or None

        # ── HMAC & Ed25519 signature verification ──────────────────────────
        self.hmac_secret = (
            hmac_secret
            or os.environ.get("GUARDIAN_FEED_HMAC_SECRET", "").strip()
            or None
        )
        self.ed25519_pubkey = (
            ed25519_pubkey
            or os.environ.get("GUARDIAN_FEED_ED25519_PUBKEY", "").strip()
            or None
        )

        # ── Circuit breaker ────────────────────────────────────────────────
        self._circuit = CircuitBreaker(
            max_failures=circuit_breaker_max_failures,
            cooldown_seconds=circuit_breaker_cooldown,
        )

        # ── Live API config ────────────────────────────────────────────────
        self._live_apis_config = live_apis_config or {}

        # ── TTL ────────────────────────────────────────────────────────────
        self._default_ttl_days = default_ttl_days  # None = never expire

        # ── Pattern state (PatternEntry list) ─────────────────────────────
        self._entries: List[PatternEntry] = []
        self._hashes: Dict[str, str] = {}
        self._match_counts: Dict[str, int] = {}
        self._last_updated: Optional[float] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        # ── Boot sequence ──────────────────────────────────────────────────
        self._load_local(self.local_fallback)
        if self._live_apis_config:
            self._pull_live_apis()
        if self.feed_url:
            self._thread = threading.Thread(target=self._auto_update, daemon=True)
            self._thread.start()

    # ── Convenience properties for backward compat ────────────────────────

    @property
    def patterns(self) -> List[str]:
        with self._lock:
            return [e.pattern for e in self._entries if not e.is_expired]

    @property
    def _compiled(self) -> List[re.Pattern]:
        with self._lock:
            return [e.compiled for e in self._entries if e.compiled and not e.is_expired]

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def match(self, text: str) -> Optional[Dict]:
        """
        Test *text* against all active (non-expired) patterns.
        Returns dict {pattern, severity, category} for first match, or None if safe.
        Also increments per-pattern hit counter.
        """
        normalized = text.lower()
        with self._lock:
            for entry in self._entries:
                if entry.is_expired or not entry.compiled:
                    continue
                if entry.compiled.search(normalized):
                    self._match_counts[entry.pattern] = (
                        self._match_counts.get(entry.pattern, 0) + 1
                    )
                    return {
                        "pattern": entry.pattern,
                        "severity": entry.severity,
                        "category": entry.category,
                        "source": entry.source,
                    }
        return None

    def add_pattern(
        self,
        pattern: str,
        severity: str = DEFAULT_SEVERITY,
        category: str = "brain_patch",
        source: str = "brain",
        ttl_days: Optional[int] = None,
    ) -> bool:
        """
        Admin/Brain API: hot-add a single pattern at runtime.
        Returns True if added, False if duplicate or invalid.
        """
        with self._lock:
            existing = {e.pattern for e in self._entries}
            if pattern in existing:
                logger.debug(f"[ThreatFeed] add_pattern: duplicate skipped: {pattern[:60]!r}")
                return False

        if not self._is_safe_regex(pattern):
            logger.warning(f"[ThreatFeed] add_pattern: unsafe regex rejected: {pattern[:60]!r}")
            return False

        entry = PatternEntry(
            pattern=pattern,
            severity=severity,
            category=category,
            source=source,
            added_at=time.time(),
            ttl_days=ttl_days if ttl_days is not None else self._default_ttl_days,
            compiled=re.compile(pattern, re.IGNORECASE),
        )
        with self._lock:
            self._entries.append(entry)
            self._last_updated = time.time()

        logger.info(f"[ThreatFeed] Hot-patched: [{severity}] {pattern[:60]!r} (source={source})")
        return True

    def remove_pattern(self, pattern: str) -> bool:
        """Admin API: remove a pattern by exact string."""
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if e.pattern != pattern]
            removed = len(self._entries) < before
        if removed:
            logger.info(f"[ThreatFeed] Removed pattern: {pattern[:60]!r}")
        return removed

    def dump_patterns(self) -> List[Dict]:
        """Admin API: return all active patterns with metadata."""
        now = time.time()
        with self._lock:
            return [
                {
                    "pattern": e.pattern,
                    "severity": e.severity,
                    "category": e.category,
                    "source": e.source,
                    "hits": self._match_counts.get(e.pattern, 0),
                    "age_days": round((now - e.added_at) / 86400, 1),
                    "ttl_days": e.ttl_days,
                    "expired": e.is_expired,
                }
                for e in self._entries
            ]

    def purge_expired(self) -> int:
        """Remove all expired patterns. Returns count removed."""
        with self._lock:
            before = len(self._entries)
            self._entries = [e for e in self._entries if not e.is_expired]
            removed = before - len(self._entries)
        if removed:
            logger.info(f"[ThreatFeed] Purged {removed} expired patterns")
        return removed

    def fetch_latest(self):
        """Fetch all remote feeds and live APIs, reload if content changed."""
        urls = [self.feed_url] if self.feed_url else []
        urls.extend(self.additional_feeds)

        all_entries: List[PatternEntry] = []

        for url in urls:
            if self._circuit.is_open(url):
                logger.warning(f"[ThreatFeed] Circuit breaker open for {url} — skipping")
                continue
            fetched = self._fetch_remote(url)
            if fetched is not None:
                all_entries.extend(fetched)
                self._circuit.record_success(url)
            else:
                self._circuit.record_failure(url)

        # Local bundled feed
        all_entries.extend(self._read_local(self.local_fallback))

        # Live API patterns (no severity info — default medium)
        if self._live_apis_config:
            live_patterns = self._pull_live_apis()
            for p in live_patterns:
                all_entries.append(PatternEntry(
                    pattern=p, severity="medium", category="live_api", source="live_api"
                ))

        if all_entries:
            self._merge_entries(all_entries)

    def refresh_now(self):
        """Admin-callable: force immediate synchronous feed refresh."""
        logger.info("[ThreatFeed] Manual refresh triggered")
        self.fetch_latest()

    def status(self) -> dict:
        """Return full status for /health and monitoring."""
        with self._lock:
            active = [e for e in self._entries if not e.is_expired]
            expired = [e for e in self._entries if e.is_expired]
            by_severity = {}
            for e in active:
                by_severity[e.severity] = by_severity.get(e.severity, 0) + 1

        top_patterns = sorted(
            self._match_counts.items(), key=lambda x: x[1], reverse=True
        )[:5]

        return {
            "pattern_count": len(active),
            "expired_count": len(expired),
            "patterns_by_severity": by_severity,
            "remote_url": self.feed_url,
            "additional_feeds": self.additional_feeds,
            "local_fallback": self.local_fallback,
            "api_key_configured": bool(self.api_key),
            "hmac_verification": bool(self.hmac_secret),
            "live_apis_enabled": [
                k for k, v in self._live_apis_config.items()
                if isinstance(v, dict) and v.get("enabled")
            ],
            "last_updated": self._last_updated,
            "feed_hashes": {k: v[:8] + "..." for k, v in self._hashes.items()},
            "circuit_breaker": {
                url: {
                    "failures": self._circuit._failures.get(url, 0),
                    "open": self._circuit.is_open(url),
                }
                for url in ([self.feed_url] if self.feed_url else []) + self.additional_feeds
            },
            "top_matched_patterns": [
                {"pattern": p[:80], "hits": c} for p, c in top_patterns
            ],
        }

    def stop(self):
        """Signal background thread to stop."""
        self._stop_event.set()

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _auth_headers(self) -> dict:
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

    def _verify_signature(self, content: str, signature_header: str) -> bool:
        """
        Verify signature from X-Feed-Signature header.
        Supports:
        - HMAC-SHA256: sha256=<hex_digest>
        - Ed25519: ed25519=<hex_signature>
        
        Returns True if valid (or if no signature keys are configured).
        """
        if not self.hmac_secret and not self.ed25519_pubkey:
            return True  # No verification keys configured — accept all
            
        if not signature_header:
            logger.warning("[ThreatFeed] Signature: no X-Feed-Signature header — rejecting feed")
            return False
            
        try:
            algo, received_hex = signature_header.split("=", 1)
            
            if algo == "sha256" and self.hmac_secret:
                expected = hmac.new(
                    self.hmac_secret.encode(),
                    content.encode(),
                    hashlib.sha256,
                ).hexdigest()
                valid = hmac.compare_digest(expected, received_hex)
                if not valid:
                    logger.error("[ThreatFeed] HMAC signature MISMATCH — feed may be tampered!")
                return valid
                
            elif algo == "ed25519" and self.ed25519_pubkey:
                try:
                    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                    pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.ed25519_pubkey))
                    pub_key.verify(bytes.fromhex(received_hex), content.encode())
                    return True
                except ImportError:
                    logger.error("[ThreatFeed] cryptography package required for Ed25519 verification")
                    return False
                except Exception as e:
                    logger.error(f"[ThreatFeed] Ed25519 signature MISMATCH — feed may be tampered! {e}")
                    return False
                    
            else:
                logger.warning(f"[ThreatFeed] Signature: unsupported algorithm or missing key for: {algo}")
                return False
                
        except Exception as e:
            logger.error(f"[ThreatFeed] Signature verification error: {e}")
            return False

    def _parse_pattern_entry(self, raw, source: str = "remote") -> Optional[PatternEntry]:
        """Parse a pattern from YAML — either plain string or rich dict."""
        if isinstance(raw, str):
            return PatternEntry(
                pattern=raw,
                severity=DEFAULT_SEVERITY,
                category="unknown",
                source=source,
                ttl_days=self._default_ttl_days,
            )
        elif isinstance(raw, dict):
            return PatternEntry(
                pattern=raw.get("pattern", ""),
                severity=raw.get("severity", DEFAULT_SEVERITY),
                category=raw.get("category", "unknown"),
                source=raw.get("source", source),
                ttl_days=raw.get("ttl_days", self._default_ttl_days),
            )
        return None

    def _load_local(self, path: str):
        entries = self._read_local(path)
        if entries:
            self._merge_entries(entries)
            logger.info(f"[ThreatFeed] Loaded {len(entries)} patterns from local feed: {path}")
        else:
            logger.warning(f"[ThreatFeed] No patterns loaded from local feed: {path}")

    def _read_local(self, path: str) -> List[PatternEntry]:
        try:
            p = Path(path)
            if not p.exists():
                return []
            content = p.read_text(encoding="utf-8")
            sha = hashlib.sha256(content.encode()).hexdigest()
            if self._hashes.get(path) == sha:
                return []  # unchanged
            self._hashes[path] = sha
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return []
            entries = []
            for raw in data.get("patterns", []):
                e = self._parse_pattern_entry(raw, source="local")
                if e:
                    entries.append(e)
            return entries
        except Exception as e:
            logger.error(f"[ThreatFeed] Failed to read local feed {path}: {e}")
            return []

    def _fetch_remote(self, url: str) -> Optional[List[PatternEntry]]:
        """
        Fetch remote YAML feed with:
        - Bearer auth header
        - SSRF redirect blocking
        - SHA-256 change detection
        - HMAC-SHA256 signature verification
        Returns None on failure (circuit breaker), [] if unchanged.
        """
        try:
            logger.info(f"[ThreatFeed] Fetching remote feed: {url}")
            resp = requests.get(
                url,
                timeout=10,
                allow_redirects=False,
                headers=self._auth_headers(),
            )

            if resp.status_code in (301, 302, 307, 308):
                logger.error(
                    f"ThreatFeed rejected due to HTTP Redirect ({resp.status_code}) to block SSRF vectors"
                )
                return None

            if resp.status_code == 401:
                logger.error(f"[ThreatFeed] 401 Unauthorized for {url} — check api_key")
                return None

            if resp.status_code != 200:
                logger.error(f"[ThreatFeed] HTTP {resp.status_code} from {url}")
                return None

            content = resp.text

            # ── Cryptographic signature verification ─────────────────────────
            sig_header = resp.headers.get("X-Feed-Signature", "")
            if not self._verify_signature(content, sig_header):
                logger.error(f"[ThreatFeed] Cryptographic signature verification failed for {url} — rejected")
                return None

            # ── SHA-256 change detection ───────────────────────────────────
            sha = hashlib.sha256(content.encode()).hexdigest()
            if self._hashes.get(url) == sha:
                logger.info(f"[ThreatFeed] No changes in feed: {url}")
                return []
            self._hashes[url] = sha

            data = yaml.safe_load(content)
            self._validate_schema(data)

            entries = []
            for raw in data.get("patterns", []):
                e = self._parse_pattern_entry(raw, source=url)
                if e:
                    entries.append(e)

            logger.info(f"[ThreatFeed] Loaded {len(entries)} patterns from {url}")
            return entries

        except requests.RequestException as e:
            logger.error(f"[ThreatFeed] Network error fetching {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"[ThreatFeed] Error fetching {url}: {e}")
            return None

    def _pull_live_apis(self) -> List[str]:
        try:
            from guardrails.live_api_feeds import fetch_all_live_patterns
            return fetch_all_live_patterns(self._live_apis_config)
        except Exception as e:
            logger.error(f"[ThreatFeed] Live API error: {e}")
            return []

    def _validate_schema(self, data: dict):
        try:
            from jsonschema import validate
            validate(instance=data, schema=self.THREAT_FEED_SCHEMA)
        except ImportError:
            pass
        except Exception as ve:
            raise ValueError(f"Invalid threat feed format: {ve}")

    @staticmethod
    def _is_safe_regex(pattern: str) -> bool:
        """
        ReDoS sandbox: compile using Google RE2 Engine.
        RE2 guarantees linear-time execution, immune to ReDoS.
        Falls back to threading sandbox if google-re2 is not installed.
        """
        try:
            import re2
            try:
                # RE2 rejects unsafe constructs (backreferences, lookarounds)
                re2.compile(pattern, _re2_ignorecase())
                return True
            except re2.error as e:
                logger.warning(f"[ThreatFeed] RE2 rejected pattern: {pattern[:60]!r} — {e}")
                return False
        except ImportError:
            # Fallback for environments without google-re2
            result = [False]
            error = [None]
    
            def _try():
                try:
                    c = re.compile(pattern, re.IGNORECASE)
                    c.search("a" * 1000)
                    result[0] = True
                except (re.error, RecursionError, OverflowError) as e:
                    error[0] = str(e)
    
            t = threading.Thread(target=_try, daemon=True)
            t.start()
            t.join(timeout=0.2)
            if t.is_alive():
                logger.warning(f"[ThreatFeed] ReDoS timeout — pattern rejected: {pattern[:60]!r}")
                return False
            if error[0]:
                logger.warning(f"[ThreatFeed] Invalid/unsafe regex: {pattern[:60]!r} — {error[0]}")
                return False
            return result[0]

    def _merge_entries(self, new_entries: List[PatternEntry]):
        """
        Deduplicate, ReDoS-sandbox, compile, and merge new entries
        into the existing pattern set (additive — never wipes).
        """
        if not new_entries:
            return

        with self._lock:
            existing_patterns = {e.pattern for e in self._entries}

        added = 0
        for entry in new_entries:
            if not entry.pattern or entry.pattern in existing_patterns:
                continue

            if not self._is_safe_regex(entry.pattern):
                continue

            try:
                try:
                    import re2
                    entry.compiled = re2.compile(entry.pattern, _re2_ignorecase())
                except ImportError:
                    entry.compiled = re.compile(entry.pattern, re.IGNORECASE)
                with self._lock:
                    self._entries.append(entry)
                    existing_patterns.add(entry.pattern)
                added += 1
            except Exception as e:
                logger.error(f"[ThreatFeed] Could not compile pattern {entry.pattern[:30]!r}: {e}")
        
        if added:
            with self._lock:
                self._last_updated = time.time()
            logger.info(f"[ThreatFeed] Merged {added} new patterns (total: {len(self._entries)})")

    def _update_patterns(self, new_patterns: List[str]):
        """Legacy compatibility wrapper for plain string pattern lists."""
        if not new_patterns:
            return
        entries = [PatternEntry(pattern=p, source="legacy") for p in new_patterns]
        self._merge_entries(entries)

    # ──────────────────────────────────────────────────────────────────────────
    # Enterprise Features: Test, Export, Metrics, Webhook, Stale Alert
    # ──────────────────────────────────────────────────────────────────────────

    def test_prompt(self, text: str) -> dict:
        """
        Dry-run match: test if a prompt would trigger a pattern, without
        incrementing hit counts or affecting any state.
        Returns {matched: bool, result: {pattern, severity, category} or None}.
        """
        normalized = text.lower()
        with self._lock:
            for entry in self._entries:
                if entry.is_expired or not entry.compiled:
                    continue
                if entry.compiled.search(normalized):
                    return {
                        "matched": True,
                        "result": {
                            "pattern": entry.pattern,
                            "severity": entry.severity,
                            "category": entry.category,
                            "source": entry.source,
                        },
                    }
        return {"matched": False, "result": None}

    def export_yaml(self) -> str:
        """Export all active (non-expired) patterns as a YAML string for backup/compliance."""
        with self._lock:
            active = [e for e in self._entries if not e.is_expired]

        export_data = {
            "version": time.strftime("%Y-%m-%d"),
            "description": f"GuardianAI threat feed export — {len(active)} patterns",
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "patterns": [],
        }
        for e in active:
            export_data["patterns"].append({
                "pattern": e.pattern,
                "severity": e.severity,
                "category": e.category,
                "source": e.source,
                "ttl_days": e.ttl_days,
            })

        return yaml.dump(export_data, default_flow_style=False, sort_keys=False)

    def prometheus_metrics(self) -> str:
        """
        Export metrics in Prometheus text exposition format.
        Suitable for scraping by Prometheus/Grafana.
        """
        with self._lock:
            active = [e for e in self._entries if not e.is_expired]
            expired_count = sum(1 for e in self._entries if e.is_expired)
            by_severity = {}
            by_source = {}
            for e in active:
                by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
                by_source[e.source] = by_source.get(e.source, 0) + 1

        total_matches = sum(self._match_counts.values())
        feed_age = time.time() - self._last_updated if self._last_updated else -1

        lines = [
            "# HELP guardian_threat_feed_patterns_total Total active threat patterns",
            "# TYPE guardian_threat_feed_patterns_total gauge",
            f"guardian_threat_feed_patterns_total {len(active)}",
            "",
            "# HELP guardian_threat_feed_expired_total Expired patterns pending purge",
            "# TYPE guardian_threat_feed_expired_total gauge",
            f"guardian_threat_feed_expired_total {expired_count}",
            "",
            "# HELP guardian_threat_feed_matches_total Total pattern match events",
            "# TYPE guardian_threat_feed_matches_total counter",
            f"guardian_threat_feed_matches_total {total_matches}",
            "",
            "# HELP guardian_threat_feed_age_seconds Seconds since last feed update",
            "# TYPE guardian_threat_feed_age_seconds gauge",
            f"guardian_threat_feed_age_seconds {feed_age:.1f}",
            "",
            "# HELP guardian_threat_feed_patterns_by_severity Patterns grouped by severity",
            "# TYPE guardian_threat_feed_patterns_by_severity gauge",
        ]
        for sev in ["critical", "high", "medium", "low"]:
            lines.append(f'guardian_threat_feed_patterns_by_severity{{severity="{sev}"}} {by_severity.get(sev, 0)}')

        lines.append("")
        lines.append("# HELP guardian_threat_feed_patterns_by_source Patterns grouped by source")
        lines.append("# TYPE guardian_threat_feed_patterns_by_source gauge")
        for src, cnt in sorted(by_source.items()):
            lines.append(f'guardian_threat_feed_patterns_by_source{{source="{src}"}} {cnt}')

        # Circuit breaker state
        lines.append("")
        lines.append("# HELP guardian_threat_feed_circuit_open Circuit breaker open state (1=open)")
        lines.append("# TYPE guardian_threat_feed_circuit_open gauge")
        all_urls = ([self.feed_url] if self.feed_url else []) + self.additional_feeds
        for url in all_urls:
            state = 1 if self._circuit.is_open(url) else 0
            safe_url = url.replace('"', '\\"')
            lines.append(f'guardian_threat_feed_circuit_open{{url="{safe_url}"}} {state}')

        lines.append("")
        return "\n".join(lines) + "\n"

    def ingest_webhook(self, payload: dict) -> dict:
        """
        Accept patterns from external SIEM/SOAR webhook push.
        
        Expected payload:
          {
            "patterns": [
              {"pattern": "...", "severity": "high", "category": "..."},
              "plain_string_pattern",
              ...
            ],
            "source": "splunk",
            "ttl_days": 7
          }
        
        Returns: {accepted: int, rejected: int, total: int}
        """
        raw_patterns = payload.get("patterns", [])
        default_source = payload.get("source", "webhook")
        default_ttl = payload.get("ttl_days")

        accepted = 0
        rejected = 0

        for raw in raw_patterns:
            if isinstance(raw, str):
                pat = raw
                sev = DEFAULT_SEVERITY
                cat = "webhook"
            elif isinstance(raw, dict):
                pat = raw.get("pattern", "")
                sev = raw.get("severity", DEFAULT_SEVERITY)
                cat = raw.get("category", "webhook")
            else:
                rejected += 1
                continue

            if not pat:
                rejected += 1
                continue

            if self.add_pattern(
                pattern=pat,
                severity=sev,
                category=cat,
                source=default_source,
                ttl_days=default_ttl,
            ):
                accepted += 1
            else:
                rejected += 1

        logger.info(f"[ThreatFeed] Webhook ingested: {accepted} accepted, {rejected} rejected")
        return {"accepted": accepted, "rejected": rejected, "total": len(raw_patterns)}

    def is_stale(self) -> bool:
        """Check if the feed hasn't been updated for > 2× update_interval."""
        if self._last_updated is None:
            return True
        age = time.time() - self._last_updated
        return age > (self.update_interval * 2)

    def _auto_update(self):
        """Background thread: periodic feed refresh + TTL purge + stale alerting."""
        while not self._stop_event.is_set():
            try:
                self.fetch_latest()
                self.purge_expired()
                # Stale feed alerting
                if self.is_stale():
                    logger.warning(
                        f"[ThreatFeed] STALE FEED ALERT: no update for "
                        f"{(time.time() - (self._last_updated or 0)) / 3600:.1f}h "
                        f"(threshold: {self.update_interval * 2 / 3600:.1f}h)"
                    )
            except Exception as e:
                logger.error(f"[ThreatFeed] Auto-update error: {e}")
            self._stop_event.wait(self.update_interval)
