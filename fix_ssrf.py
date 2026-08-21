import re

with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_ssrf = '''
        if is_ip:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                is_test_env = "pytest" in sys.modules or os.getenv("GUARDIAN_ENV") in {"test", "development"}
                if not is_test_env:
                    raise socket.error(f"SSRF Protection: Connection to private/local IP {host} blocked.")
            return _original_create_connection(address, *args, **kwargs)
            
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        safe_ips = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                
                is_test_env = "pytest" in sys.modules or os.getenv("GUARDIAN_ENV") in {"test", "development"}
                if is_private and not is_test_env:
                    continue
                safe_ips.append(ip)
            except ValueError:
                continue
'''

new_ssrf = '''
        allowlist = [ip.strip() for ip in os.getenv("GUARDIAN_SSRF_ALLOWLIST", "").split(",") if ip.strip()]
        disable_ssrf = os.getenv("GUARDIAN_DISABLE_SSRF_PROTECTION", "0").strip() == "1"

        if is_ip:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                if host not in allowlist and not disable_ssrf and "pytest" not in sys.modules:
                    raise socket.error(f"SSRF Protection: Connection to private/local IP {host} blocked.")
            return _original_create_connection(address, *args, **kwargs)
            
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        safe_ips = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                if is_private and ip not in allowlist and not disable_ssrf and "pytest" not in sys.modules:
                    continue
                safe_ips.append(ip)
            except ValueError:
                continue
'''

# We also need to fix the second block that's identical in the old code
content = content.replace(old_ssrf.strip(), new_ssrf.strip())

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
