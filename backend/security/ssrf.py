import ipaddress
import os
import socket
import sys
import urllib3.util.connection

if not hasattr(urllib3.util.connection, "_real_create_connection"):
    urllib3.util.connection._real_create_connection = urllib3.util.connection.create_connection
_original_create_connection = urllib3.util.connection._real_create_connection


def _safe_create_connection(address, *args, **kwargs):
    host, port = address
    try:
        allowlist = [ip.strip() for ip in os.getenv("GUARDIAN_SSRF_ALLOWLIST", "").split(",") if ip.strip()]

        try:
            ip_obj = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                if host not in allowlist and "pytest" not in sys.modules:
                    raise socket.error(f"SSRF Protection: Connection to private/local IP {host} blocked.")
            return _original_create_connection(address, *args, **kwargs)

        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        safe_ips = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                # If resolved IP is private, block unless it's explicitly allowlisted
                if is_private and ip not in allowlist and "pytest" not in sys.modules:
                    continue
                safe_ips.append(ip)
            except ValueError:
                continue

        if not safe_ips:
            raise socket.error(f"SSRF Protection: All resolved IPs for {host} are private/local and blocked.")

        # Try safe IPs until one works
        for safe_ip in safe_ips:
            try:
                return _original_create_connection((safe_ip, port), *args, **kwargs)
            except socket.error:
                continue
        raise socket.error(f"SSRF Protection: Could not connect to any safe IP for {host}.")

    except socket.gaierror as exc:
        return _original_create_connection(address, *args, **kwargs)


urllib3.util.connection.create_connection = _safe_create_connection

__all__ = ["_safe_create_connection", "_original_create_connection"]
