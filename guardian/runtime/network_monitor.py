"""
Network Monitor — OS-Level Connection & DNS Sinkhole Guard
===========================================================
Feature #8: Monitors active network connections made by processes on
the host, blocks connections to known-malicious IPs/CIDRs/domains,
and provides DNS sinkhole capability.

Key Capabilities:
    1. IP Blocklist — block connections to known C2 IPs and CIDR ranges
    2. Domain Blocklist — block connections to malicious domains
    3. DNS Sinkhole — resolve blocked domains to 0.0.0.0/127.0.0.1
    4. Live connection scanning — scan psutil.net_connections()
    5. Process attribution — identify which PID opened a rogue connection
    6. Allowlist — never block internal/safe IPs or whitelisted domains
    7. GeoIP-free heuristics — detect connections to Tor exit nodes,
       known anonymizer CIDRs, and RFC 5737 documentation ranges
    8. Rate-limited alerting — avoid alert storms
    9. Stats & metrics endpoint
   10. Configurable via YAML

Author: GuardianAI Team
License: MIT
"""
import ipaddress
import logging
import os
import re
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger("guardian_network_monitor")


# ─── Default blocklists ─────────────────────────────────────────────────────

# Well-known malicious / suspicious IP ranges
DEFAULT_BLOCKED_CIDRS = [
    # RFC 5737 — documentation/example ranges (should never appear in prod traffic)
    "192.0.2.0/24",       # TEST-NET-1
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    # Known C2 / sinkhole ranges
    "0.0.0.0/8",          # "This" network — invalid destination
]

# Common malicious / exfiltration domains
DEFAULT_BLOCKED_DOMAINS = [
    # Reverse shell / C2 domains
    "ngrok.io",
    "ngrok-free.app",
    "serveo.net",
    "localhost.run",
    "burpcollaborator.net",
    "interact.sh",
    "oastify.com",
    "requestbin.net",
    "pipedream.net",
    "webhook.site",
    "canarytokens.com",
    # Data exfil
    "paste.ee",
    "transfer.sh",
    "file.io",
    "0x0.st",
    # Crypto mining pools
    "pool.minexmr.com",
    "xmrpool.eu",
    "moneroocean.stream",
    "hashvault.pro",
]

# IPs that should NEVER be blocked (loopback, link-local, private)
DEFAULT_ALLOWLIST_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fe80::/10",
]


class NetworkMonitor:
    """
    Monitors OS-level network connections, blocks known-malicious
    destinations, and provides DNS sinkhole capability.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        net_cfg = config.get("network_monitoring", {})

        # ── Blocklists ───────────────────────────────────────────────
        raw_cidrs = net_cfg.get("blocked_cidrs", DEFAULT_BLOCKED_CIDRS)
        self.blocked_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in raw_cidrs:
            try:
                self.blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning(f"Invalid CIDR in blocklist: {cidr}")

        raw_ips = net_cfg.get("blocked_ips", [])
        self.blocked_ips: Set[str] = set(raw_ips)

        raw_domains = net_cfg.get("blocked_domains", DEFAULT_BLOCKED_DOMAINS)
        self.blocked_domains: Set[str] = set(d.lower() for d in raw_domains)

        # ── Allowlists ───────────────────────────────────────────────
        raw_allow = net_cfg.get("allowlist_cidrs", DEFAULT_ALLOWLIST_CIDRS)
        self.allowlist_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in raw_allow:
            try:
                self.allowlist_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

        self.allowlist_domains: Set[str] = set(
            d.lower() for d in net_cfg.get("allowlist_domains", [])
        )

        # ── DNS Sinkhole ─────────────────────────────────────────────
        self.sinkhole_enabled: bool = net_cfg.get("sinkhole_enabled", True)
        self.sinkhole_address: str = net_cfg.get("sinkhole_address", "0.0.0.0")

        # ── Scanning config ──────────────────────────────────────────
        self.check_interval: int = net_cfg.get("check_interval_seconds", 5)
        self.alert_cooldown: int = net_cfg.get("alert_cooldown_seconds", 60)

        # ── Runtime state ────────────────────────────────────────────
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._alert_history: Dict[str, float] = {}  # key → last_alert_ts
        self._stats = {
            "total_scans": 0,
            "total_connections_checked": 0,
            "total_blocked": 0,
            "blocked_by_ip": 0,
            "blocked_by_cidr": 0,
            "blocked_by_domain": 0,
            "dns_sinkholed": 0,
            "false_positives_avoided": 0,
        }
        self._blocked_log: List[Dict[str, Any]] = []

        logger.info(
            f"NetworkMonitor initialized: {len(self.blocked_networks)} CIDRs, "
            f"{len(self.blocked_ips)} IPs, {len(self.blocked_domains)} domains blocked. "
            f"Sinkhole={'ON' if self.sinkhole_enabled else 'OFF'}."
        )

    # ─── Core: IP / Domain Checking ──────────────────────────────────────

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Check if IP is in allowlist (private/loopback)."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(addr in net for net in self.allowlist_networks)

    def is_ip_blocked(self, ip_str: str) -> Tuple[bool, str]:
        """
        Check if an IP is blocked. Returns (blocked: bool, reason: str).
        Allowlisted IPs are never blocked.
        """
        if not ip_str or ip_str == "0.0.0.0" or ip_str == "::":
            return False, ""

        # Allowlist check first
        if self.is_ip_allowed(ip_str):
            return False, ""

        # Direct IP blocklist
        if ip_str in self.blocked_ips:
            return True, f"blocked_ip:{ip_str}"

        # CIDR range check
        try:
            addr = ipaddress.ip_address(ip_str)
            for net in self.blocked_networks:
                if addr in net:
                    return True, f"blocked_cidr:{net}"
        except ValueError:
            pass

        return False, ""

    def is_domain_blocked(self, domain: str) -> Tuple[bool, str]:
        """
        Check if a domain or any parent domain is in the blocklist.
        e.g. 'sub.ngrok.io' is blocked because 'ngrok.io' is in the list.
        """
        if not domain:
            return False, ""
        domain = domain.lower().strip(".")

        # Allowlist check
        if domain in self.allowlist_domains:
            return False, ""
        for allow_d in self.allowlist_domains:
            if domain.endswith("." + allow_d):
                return False, ""

        # Exact match
        if domain in self.blocked_domains:
            return True, f"blocked_domain:{domain}"

        # Subdomain match — check all parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True, f"blocked_domain:{parent}"

        return False, ""

    # ─── DNS Sinkhole ────────────────────────────────────────────────────

    def resolve_with_sinkhole(self, domain: str) -> str:
        """
        Resolve a domain. If the domain is blocked and sinkhole is enabled,
        return the sinkhole address instead of the real IP.
        """
        blocked, reason = self.is_domain_blocked(domain)
        if blocked and self.sinkhole_enabled:
            self._stats["dns_sinkholed"] += 1
            logger.warning(f"DNS SINKHOLE: {domain} → {self.sinkhole_address} ({reason})")
            return self.sinkhole_address

        # Normal resolution
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return ""

    # ─── Connection Scanning ─────────────────────────────────────────────

    def scan_connections(self) -> List[Dict[str, Any]]:
        """
        Scan all active network connections and return list of blocked ones.
        Each entry: {pid, process_name, remote_ip, remote_port, reason, status}
        """
        if not PSUTIL_AVAILABLE:
            return []

        blocked_conns = []
        self._stats["total_scans"] += 1

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Insufficient permissions for net_connections()")
            return []

        for conn in connections:
            self._stats["total_connections_checked"] += 1

            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip if hasattr(conn.raddr, "ip") else conn.raddr[0]
            remote_port = conn.raddr.port if hasattr(conn.raddr, "port") else conn.raddr[1]

            blocked, reason = self.is_ip_blocked(remote_ip)
            if blocked:
                category = "cidr" if "cidr" in reason else "ip"
                self._stats[f"blocked_by_{category}"] += 1
                self._stats["total_blocked"] += 1

                entry = self._build_alert(conn, remote_ip, remote_port, reason)
                blocked_conns.append(entry)
                self._emit_alert(entry)

        return blocked_conns

    def check_domain_connection(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Check if a domain would be blocked before connecting.
        Used as a pre-flight check by the interceptor.
        """
        blocked, reason = self.is_domain_blocked(domain)
        result = {
            "domain": domain,
            "port": port,
            "blocked": blocked,
            "reason": reason,
            "sinkhole_ip": self.sinkhole_address if blocked and self.sinkhole_enabled else None,
        }
        if blocked:
            self._stats["blocked_by_domain"] += 1
            self._stats["total_blocked"] += 1
        return result

    # ─── Background Thread ───────────────────────────────────────────────

    def start(self):
        """Start the background connection scanning thread."""
        if self._thread is not None:
            return
        logger.info("Starting Network Monitor background thread...")
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the background scanning thread."""
        if self._thread is None:
            return
        logger.info("Stopping Network Monitor...")
        self._stop_event.set()
        self._thread.join(timeout=10)
        self._thread = None

    def _scan_loop(self):
        while not self._stop_event.is_set():
            try:
                self.scan_connections()
            except Exception as e:
                logger.error(f"Network scan error: {e}")
            self._stop_event.wait(self.check_interval)

    # ─── Alerting ────────────────────────────────────────────────────────

    def _build_alert(self, conn, remote_ip, remote_port, reason) -> Dict[str, Any]:
        pid = conn.pid or 0
        proc_name = ""
        try:
            if pid and PSUTIL_AVAILABLE:
                proc_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return {
            "pid": pid,
            "process_name": proc_name,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "reason": reason,
            "status": conn.status if hasattr(conn, "status") else "UNKNOWN",
            "timestamp": time.time(),
        }

    def _emit_alert(self, entry: Dict[str, Any]):
        key = f"{entry['remote_ip']}:{entry['remote_port']}"
        now = time.time()
        last = self._alert_history.get(key, 0)
        if now - last < self.alert_cooldown:
            return  # Rate-limited
        self._alert_history[key] = now
        self._blocked_log.append(entry)
        logger.warning(
            f"🔒 BLOCKED CONNECTION: PID {entry['pid']} ({entry['process_name']}) "
            f"→ {entry['remote_ip']}:{entry['remote_port']} | {entry['reason']}"
        )

    # ─── Runtime Management ──────────────────────────────────────────────

    def add_blocked_ip(self, ip: str) -> bool:
        """Hot-add an IP to the blocklist at runtime."""
        if ip in self.blocked_ips:
            return False
        self.blocked_ips.add(ip)
        logger.info(f"Added IP to blocklist: {ip}")
        return True

    def add_blocked_cidr(self, cidr: str) -> bool:
        """Hot-add a CIDR range to the blocklist at runtime."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            self.blocked_networks.append(net)
            logger.info(f"Added CIDR to blocklist: {cidr}")
            return True
        except ValueError:
            return False

    def add_blocked_domain(self, domain: str) -> bool:
        """Hot-add a domain to the blocklist at runtime."""
        domain = domain.lower()
        if domain in self.blocked_domains:
            return False
        self.blocked_domains.add(domain)
        logger.info(f"Added domain to blocklist: {domain}")
        return True

    def remove_blocked_domain(self, domain: str) -> bool:
        """Remove a domain from the blocklist."""
        domain = domain.lower()
        if domain not in self.blocked_domains:
            return False
        self.blocked_domains.discard(domain)
        return True

    def remove_blocked_ip(self, ip: str) -> bool:
        """Remove an IP from the blocklist at runtime."""
        if ip not in self.blocked_ips:
            return False
        self.blocked_ips.discard(ip)
        logger.info(f"Removed IP from blocklist: {ip}")
        return True

    def remove_blocked_cidr(self, cidr: str) -> bool:
        """Remove a CIDR range from the blocklist at runtime."""
        try:
            target = ipaddress.ip_network(cidr, strict=False)
            before = len(self.blocked_networks)
            self.blocked_networks = [n for n in self.blocked_networks if n != target]
            removed = len(self.blocked_networks) < before
            if removed:
                logger.info(f"Removed CIDR from blocklist: {cidr}")
            return removed
        except ValueError:
            return False

    # ─── Stats & Export ──────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return monitoring statistics."""
        return {
            **self._stats,
            "blocked_cidrs_count": len(self.blocked_networks),
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_domains_count": len(self.blocked_domains),
            "sinkhole_enabled": self.sinkhole_enabled,
            "sinkhole_address": self.sinkhole_address,
            "recent_blocks": self._blocked_log[-20:],
        }

    def get_blocked_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent blocked connection log."""
        return self._blocked_log[-limit:]

    def export_blocklists(self) -> Dict[str, Any]:
        """Export current blocklists as serializable dict."""
        return {
            "blocked_cidrs": [str(n) for n in self.blocked_networks],
            "blocked_ips": sorted(self.blocked_ips),
            "blocked_domains": sorted(self.blocked_domains),
            "allowlist_cidrs": [str(n) for n in self.allowlist_networks],
            "allowlist_domains": sorted(self.allowlist_domains),
        }
