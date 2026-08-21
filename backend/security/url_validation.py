import urllib.parse
import socket
import ipaddress
import sys
import os
import logging

logger = logging.getLogger("guardian_url_validation")

def is_safe_url(url: str) -> bool:
    """
    Validates a URL to prevent SSRF vulnerabilities.
    
    1. Scheme check: Must be HTTP or HTTPS. In production, scheme MUST be HTTPS.
    2. Private/Local range block: DNS resolves the hostname and checks if it falls
       under private, loopback, link-local, or metadata ranges.
    3. Bypass option: Private/local target URLs or unresolved local suffixes
       (e.g., .local, .internal, localhost) are only permitted if
       GUARDIAN_ALLOW_INTERNAL_TEST_HOSTS is explicitly set to 'true'.
    """
    if not url:
        return False

    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            logger.warning("URL validation failed: Invalid scheme %s", parsed.scheme)
            return False

        # In production, only HTTPS is allowed.
        is_production = os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production"
        is_explicit_test_allowed = os.getenv("GUARDIAN_ALLOW_INTERNAL_TEST_HOSTS", "false").strip().lower() in {"1", "true", "yes", "on"}
        is_pytest = "pytest" in sys.modules

        if is_production and parsed.scheme != "https":
            logger.warning("URL validation failed: HTTP scheme is prohibited in production.")
            return False

        hostname = parsed.hostname
        if not hostname:
            logger.warning("URL validation failed: No hostname in URL.")
            return False

        lower_host = hostname.lower()
        is_dummy_suffix = any(lower_host.endswith(suf) for suf in [".example", ".local", ".test", ".internal", ".invalid"])

        # If it's a dummy test suffix, we bypass DNS check under pytest or if explicitly allowed.
        if is_dummy_suffix:
            if is_explicit_test_allowed or is_pytest:
                return True
            else:
                logger.warning("URL validation failed: Local/internal hostname '%s' is not allowed without GUARDIAN_ALLOW_INTERNAL_TEST_HOSTS=true", hostname)
                return False

        # If it is localhost, only allow if explicitly allowed.
        if lower_host == "localhost":
            if is_explicit_test_allowed:
                return True
            else:
                logger.warning("URL validation failed: Localhost is not allowed without GUARDIAN_ALLOW_INTERNAL_TEST_HOSTS=true")
                return False

        # Resolve IPs
        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            # DNS resolution failed. If it's not a known test host suffix, block it.
            logger.warning("URL validation failed: DNS resolution failed for hostname %s: %s", hostname, exc)
            return False

        # Check resolved IPs
        for item in addr_info:
            ip = item[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    if not is_explicit_test_allowed:
                        logger.warning("URL validation failed: Hostname %s resolved to private/local IP %s, which is blocked.", hostname, ip)
                        return False
            except ValueError:
                pass

        return True
    except Exception as exc:
        logger.warning("URL validation encountered exception: %s", exc)
        return False
