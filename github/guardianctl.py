#!/usr/bin/env python3
"""
GuardianAI cross-platform launcher.

This script gives a single command surface for Windows/macOS/Linux:
  - setup (wizard)
  - start (backend + proxy)
  - status (health checks)
"""

import argparse
import ipaddress
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin

import yaml

ROOT = Path(__file__).resolve().parent
RISKY_PORTS = {8080, 6333, 8000}


def parse_host_port(endpoint: str):
    value = endpoint.strip()
    if not value:
        return None, None

    # Windows netstat can render IPv6 binds as :::8080.
    if value.startswith(":::"):
        return "::", int(value.split(":")[-1])

    if value.startswith("[") and "]" in value:
        host, _, remainder = value.partition("]")
        host = host.lstrip("[")
        remainder = remainder.lstrip(":")
        if remainder.isdigit():
            return host, int(remainder)
        return host, None

    if ":" not in value:
        return value, None

    host, port_text = value.rsplit(":", 1)
    if not port_text.isdigit():
        return host, None
    return host, int(port_text)


def is_exposed_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized in {"127.0.0.1", "localhost", "::1"}:
        return False
    if normalized in {"0.0.0.0", "::", "*", ":::", "[::]"}:
        return True
    try:
        ip = ipaddress.ip_address(normalized)
        return not ip.is_loopback
    except ValueError:
        # If we cannot parse it as an IP, treat it as exposed to be safe.
        return True


def get_listening_endpoints():
    endpoints = []
    if os.name == "nt":
        cmd = ["netstat", "-ano", "-p", "tcp"]
    else:
        cmd = ["sh", "-c", "ss -ltn || netstat -ltn"]
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except Exception:  # noqa: BLE001
        return endpoints

    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if os.name == "nt":
            if not line.upper().startswith("TCP"):
                continue
            parts = line.split()
            if len(parts) < 4 or parts[3].upper() != "LISTENING":
                continue
            host, port = parse_host_port(parts[1])
            if host and port:
                endpoints.append((host, port, line))
        else:
            if "LISTEN" not in line and not line.startswith("tcp"):
                continue
            parts = line.split()
            local = None
            if len(parts) >= 4 and parts[0].lower().startswith("tcp"):
                local = parts[3]
            if local is None:
                continue
            host, port = parse_host_port(local)
            if host and port:
                endpoints.append((host, port, line))
    return endpoints


def run_hardening_check(strict: bool = False) -> int:
    endpoints = get_listening_endpoints()
    risky_exposed = []
    for host, port, source in endpoints:
        if port in RISKY_PORTS and is_exposed_host(host):
            risky_exposed.append((host, port, source))

    if not risky_exposed:
        print("[OK] Hardening check passed. No risky ports are publicly bound.")
        return 0

    print("[WARN] Hardening check found risky public bindings:")
    for host, port, _ in risky_exposed:
        print(f"  - {host}:{port}")
    print("Close these ports or bind them to localhost before proceeding.")

    if strict:
        print("Startup blocked. Use --allow-risky-ports to bypass intentionally.")
        return 1
    return 0


def find_python_executable() -> str:
    candidates = [
        ROOT / ".venv312" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"),
        ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"),
        Path(sys.executable),
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return str(candidate)
    return "python"


def default_config_path() -> Path:
    wizard_cfg = ROOT / "guardian" / "config" / "wizard_config.yaml"
    if wizard_cfg.exists():
        return wizard_cfg
    return ROOT / "guardian" / "config" / "config.yaml"


def resolve_config_path(config_arg: str = "") -> Path:
    return Path(config_arg).resolve() if config_arg else default_config_path()


def read_target_url(config_path: Path) -> str:
    default_target = "http://127.0.0.1:8080"
    if not config_path.exists():
        return default_target
    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:  # noqa: BLE001
        return default_target
    proxy = data.get("proxy", {}) if isinstance(data, dict) else {}
    target = proxy.get("target_url", default_target)
    return str(target).rstrip("/")


def run_setup_wizard(python_exe: str) -> int:
    cmd = [python_exe, str(ROOT / "guardian" / "wizard.py")]
    return subprocess.call(cmd, cwd=str(ROOT))


def open_url(url: str) -> int:
    import webbrowser

    ok = webbrowser.open(url)
    if ok:
        print(f"Opened: {url}")
        return 0
    print(f"Could not open browser automatically. Open manually: {url}")
    return 1


def http_status(url: str, timeout: float = 2.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read(512).decode("utf-8", errors="ignore")
            return response.status, body
    except urllib.error.HTTPError as e:
        return e.code, str(e)
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def print_status(config_path: Path) -> int:
    target_url = read_target_url(config_path)
    upstream_health_url = urljoin(f"{target_url}/", "health")
    checks = {
        "OpenClaw upstream": upstream_health_url,
        "Guardian proxy": "http://127.0.0.1:8081/health",
        "Backend API": "http://127.0.0.1:8001/health",
        "Dashboard UI": "http://127.0.0.1:8001/",
    }

    failures = 0
    for name, url in checks.items():
        code, body = http_status(url)
        if code is None:
            failures += 1
            print(f"[DOWN] {name:<16} {url} ({body})")
            continue
        is_dashboard_auth_challenge = name == "Dashboard UI" and code == 401
        state = "OK" if (200 <= code < 300 or is_dashboard_auth_challenge) else "WARN"
        if state != "OK":
            failures += 1
        print(f"[{state}] {name:<16} {url} (HTTP {code})")

    return 1 if failures else 0


def start_stack(python_exe: str, config_path: Path, backend_only: bool = False) -> int:
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["GUARDIAN_CONFIG"] = str(config_path)

    backend_cmd = [python_exe, str(ROOT / "backend" / "main.py")]
    guardian_cmd = [python_exe, str(ROOT / "guardian" / "main.py")]

    backend_proc = None
    guardian_proc = None
    try:
        print("Starting backend on http://127.0.0.1:8001")
        backend_proc = subprocess.Popen(backend_cmd, cwd=str(ROOT), env=env)
        time.sleep(2)

        if not backend_only:
            print(f"Starting Guardian proxy using config: {config_path}")
            guardian_proc = subprocess.Popen(guardian_cmd, cwd=str(ROOT), env=env)

        print("Stack started.")
        print("Dashboard: http://127.0.0.1:8001 (default auth: admin / guardian_default)")
        print("Proxy:     http://127.0.0.1:8081")
        print("Press Ctrl+C to stop.")

        while True:
            time.sleep(1)
            if backend_proc and backend_proc.poll() is not None:
                print("Backend exited unexpectedly.")
                return backend_proc.returncode or 1
            if guardian_proc and guardian_proc.poll() is not None:
                print("Guardian proxy exited unexpectedly.")
                return guardian_proc.returncode or 1
    except KeyboardInterrupt:
        print("\nStopping stack...")
        return 0
    finally:
        for proc in (guardian_proc, backend_proc):
            if proc and proc.poll() is None:
                proc.terminate()
        time.sleep(1)
        for proc in (guardian_proc, backend_proc):
            if proc and proc.poll() is None:
                proc.kill()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GuardianAI cross-platform control CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("setup", help="Run interactive setup wizard")

    start = sub.add_parser("start", help="Start backend + Guardian proxy")
    start.add_argument(
        "--config",
        type=str,
        default="",
        help="Config file path. Defaults to wizard_config.yaml, then config.yaml.",
    )
    start.add_argument(
        "--backend-only",
        action="store_true",
        help="Start only backend (dashboard/API).",
    )
    start.add_argument(
        "--allow-risky-ports",
        action="store_true",
        help="Bypass hardening block if risky ports are publicly bound.",
    )

    status = sub.add_parser("status", help="Check health of upstream/proxy/backend/dashboard")
    status.add_argument(
        "--config",
        type=str,
        default="",
        help="Config file path. Defaults to wizard_config.yaml, then config.yaml.",
    )
    hardening = sub.add_parser("hardening-check", help="Check risky public port exposure")
    hardening.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero if risky public bindings are found.",
    )

    dash = sub.add_parser("dashboard", help="Open dashboard in browser")
    dash.add_argument(
        "--url",
        default="http://127.0.0.1:8001",
        help="Dashboard URL",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    python_exe = find_python_executable()

    if args.command == "setup":
        return run_setup_wizard(python_exe)

    if args.command == "status":
        return print_status(resolve_config_path(getattr(args, "config", "")))

    if args.command == "dashboard":
        return open_url(args.url)

    if args.command == "hardening-check":
        return run_hardening_check(strict=args.strict)

    if args.command == "start":
        hardening_rc = run_hardening_check(strict=not args.allow_risky_ports)
        if hardening_rc != 0:
            return hardening_rc
        cfg = resolve_config_path(args.config)
        if not cfg.exists():
            print(f"Config not found: {cfg}")
            print("Run: python guardianctl.py setup")
            return 1
        return start_stack(python_exe, cfg, backend_only=args.backend_only)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

