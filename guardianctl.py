#!/usr/bin/env python3
"""
GuardianAI cross-platform launcher.

This script gives a single command surface for Windows/macOS/Linux:
  - setup (wizard)
  - start (backend + proxy)
  - status (health checks)
"""

import argparse
import hashlib
import ipaddress
import os
import platform
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urljoin

import yaml

ROOT = Path(__file__).resolve().parent
RISKY_PORTS = {8080, 6333, 8000}
LICENSE_ACTIVATION_PATH = ROOT / "artifacts" / "control" / "license_activation.json"
LICENSE_ENFORCEMENT = os.getenv("GUARDIAN_LICENSE_ENFORCEMENT", "true").strip().lower() in {"1", "true", "yes", "on"}
LICENSE_KEY_RE = re.compile(r"^GAI-[a-f0-9]{12}-[A-Z0-9]{12}$")
LICENSE_ISSUER_SECRET = os.getenv("GUARDIAN_LICENSE_ISSUER_SECRET", "").strip()
LICENSE_KEY_ENV = "GUARDIAN_LICENSE_KEY"


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


def get_machine_fingerprint() -> str:
    raw = f"{platform.system()}|{platform.node()}|{uuid.getnode():012x}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue_license_key(machine_id: str) -> str:
    normalized = (machine_id or "").strip().lower()
    if len(normalized) < 12 or not re.fullmatch(r"[a-f0-9]+", normalized):
        raise ValueError("machine_id must be a hex fingerprint.")
    machine_part = normalized[:12]
    random_part = secrets.token_hex(6).upper()
    return f"GAI-{machine_part}-{random_part}"


def save_license_activation(license_key: str, machine_id: str) -> None:
    payload = {
        "license_key": license_key.strip(),
        "machine_id": machine_id.strip().lower(),
        "activated_at_epoch": int(time.time()),
    }
    LICENSE_ACTIVATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    LICENSE_ACTIVATION_PATH.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def load_license_activation() -> dict | None:
    if not LICENSE_ACTIVATION_PATH.exists():
        return None
    try:
        data = yaml.safe_load(LICENSE_ACTIVATION_PATH.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    return data


def load_env_license_key() -> str:
    return os.getenv(LICENSE_KEY_ENV, "").strip()


def activate_license(license_key: str) -> tuple[bool, str]:
    key = (license_key or "").strip()
    if not LICENSE_KEY_RE.fullmatch(key):
        return False, "Invalid license format."
    machine_id = get_machine_fingerprint()
    machine_part = key.split("-")[1].lower()
    if machine_part != machine_id[:12]:
        return False, "License key is bound to a different machine."
    save_license_activation(key, machine_id)
    return True, "License activated for this machine."


def can_issue_license(issuer_secret: str) -> tuple[bool, str]:
    if not LICENSE_ISSUER_SECRET:
        return False, "License issuing is disabled on this build."
    if not issuer_secret or not secrets.compare_digest(issuer_secret.strip(), LICENSE_ISSUER_SECRET):
        return False, "Invalid issuer secret."
    return True, "Issuer authorized."


def check_license_ready() -> tuple[bool, str]:
    if not LICENSE_ENFORCEMENT:
        return True, "License enforcement disabled by env."
    env_key = load_env_license_key()
    if env_key:
        ok, msg = activate_license(env_key)
        if ok:
            return True, f"License activated from {LICENSE_KEY_ENV}."
        return False, f"{LICENSE_KEY_ENV} invalid: {msg}"

    data = load_license_activation()
    if not data:
        return False, f"No activated license found. Run: guardianctl activate --license-key <key> or set {LICENSE_KEY_ENV}."
    key = str(data.get("license_key", "")).strip()
    if not LICENSE_KEY_RE.fullmatch(key):
        return False, "Stored license is invalid. Re-run activation."
    machine_id = get_machine_fingerprint()
    stored_machine = str(data.get("machine_id", "")).strip().lower()
    if stored_machine != machine_id:
        return False, "Stored license does not match this machine."
    key_machine = key.split("-")[1].lower()
    if key_machine != machine_id[:12]:
        return False, "Stored license key belongs to a different machine."
    return True, "License valid for this machine."


def generate_secret(length: int = 32) -> str:
    token = secrets.token_urlsafe(length)
    return token[:length]


def ensure_one_click_env(base_env: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    env = dict(base_env)
    generated: dict[str, str] = {}

    defaults = {
        "GUARDIAN_ADMIN_USER": "admin",
        "GUARDIAN_SERVICE_ID": "guardian-proxy",
    }
    secret_keys = (
        "GUARDIAN_ADMIN_PASS",
        "GUARDIAN_BACKEND_TOKEN",
        "GUARDIAN_SERVICE_AUTH_TOKEN",
        "GUARDIAN_ADMIN_BYPASS_TOKEN",
    )

    for key, value in defaults.items():
        if not env.get(key, "").strip():
            env[key] = value
            generated[key] = value

    for key in secret_keys:
        if not env.get(key, "").strip():
            env[key] = generate_secret(40)
            generated[key] = env[key]

    return env, generated


def build_one_click_config(
    target_url: str,
    proxy_port: int,
    backend_port: int,
    admin_bypass_token: str,
) -> dict:
    threat_feed_url = os.environ.get("GUARDIAN_THREAT_FEED_URL", "").strip()
    threat_feed_enabled = bool(threat_feed_url)
    return {
        "app_name": "GuardianAI One-Click SaaS",
        "version": "1.0.0",
        "guardian_id": "guardian-one-click",
        "governance": {
            "enabled": True,
            "mode": "audit",
            "policy_file": "config/policy_control.yaml",
        },
        "security_policies": {
            "block_prompt_injection": True,
            "validate_output": True,
            "security_mode": "strict",
            "show_block_reason": True,
            "leak_prevention_strategy": "redact",
            "admin_token": admin_bypass_token,
        },
        "scanner": {
            "skills_directory": "./mock_skills",
            "blocked_imports": ["os", "subprocess", "sys", "socket"],
            "blocked_functions": ["eval", "exec", "open"],
        },
        "runtime_monitoring": {
            "blocked_cmdline_patterns": [],
            "blocked_processes": ["nc.exe", "ncat.exe", "netcat.exe", "calc.exe"],
            "max_cpu_percent": 95.0,
            "max_memory_percent": 90.0,
            "check_interval_seconds": 2,
        },
        "proxy": {
            "enabled": True,
            "listen_port": proxy_port,
            "target_url": target_url,
        },
        "backend": {
            "enabled": True,
            "url": f"http://127.0.0.1:{backend_port}/api/v1/telemetry",
            "token": os.environ.get("GUARDIAN_BACKEND_TOKEN", "").strip(),
            "service_id": os.environ.get("GUARDIAN_SERVICE_ID", "guardian-proxy").strip() or "guardian-proxy",
            "service_auth_token": os.environ.get("GUARDIAN_SERVICE_AUTH_TOKEN", "").strip(),
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 180,
        },
        "threat_feed": {
            "enabled": threat_feed_enabled,
            "url": threat_feed_url,
            "update_interval_seconds": 3600,
        },
        "tool_policy": {
            "enabled": True,
            "preset": "openai_tools_baseline",
            "enforcement_mode": "audit",
            "unknown_tool_action": "deny",
            "confirmation_header": "X-Guardian-Tool-Confirm",
            "confirmation_value": "true",
            "allowed_tools": [],
            "denied_tools": [],
            "sensitive_tools": [],
        },
        "honeypot": {
            "enabled": True,
            "max_responses_per_window": 3,
            "window_seconds": 60,
            "min_interval_seconds": 3,
        },
        "cost_abuse": {
            "enabled": True,
            "window_seconds": 120,
            "min_events": 3,
            "max_tokens_per_window": 12000,
            "max_cost_usd_per_window": 0.60,
            "spike_multiplier": 3.50,
            "quarantine_seconds": 900,
            "cost_per_1k_tokens_usd": 0.01,
            "tenant_window_seconds": 300,
            "min_sessions_for_tenant_anomaly": 3,
            "max_tokens_per_tenant_window": 60000,
            "max_cost_usd_per_tenant_window": 3.00,
        },
        "tenant_isolation": {
            "enabled": True,
            "require_tenant_header": False,
            "tenant_header": "X-Guardian-Tenant",
            "default_tenant_id": "default",
            "enforce_tenant_scope_on_session": True,
            "tenant_evidence_dir": "artifacts/evidence/tenants",
            "allowed_tenant_pattern": "^[a-z0-9][a-z0-9_-]{1,63}$",
        },
        "agentic_security": {
            "enabled": True,
            "enforcement_mode": "audit",
            "require_agent_id": False,
            "require_execution_id": False,
            "require_scope": False,
            "max_hops": 8,
            "trusted_mcp_servers": [],
            "require_mcp_server_for_tools": False,
            "enforce_scope_non_escalation": True,
            "revoked_agent_ids": [],
            "require_agent_attestation": False,
            "agent_attestation_keys": {},
            "revoked_agent_key_ids": [],
            "require_mtls": False,
            "mtls_verified_header": "X-Guardian-mTLS-Verified",
            "mtls_fingerprint_header": "X-Guardian-mTLS-Fingerprint",
            "mtls_subject_header": "X-Guardian-mTLS-Subject",
            "mtls_verified_value": "SUCCESS",
            "agent_cert_fingerprints": {},
            "control_plane_file": "",
            "control_plane_reload_seconds": 5,
            "enforce_policy_graph": False,
            "cross_agent_policy_graph": {},
            "require_execution_grant": False,
            "execution_grants": {},
            "require_trace_hash": False,
            "trace_replay_cache_enabled": False,
            "trace_replay_cache_file": "artifacts/control/agent_trace_hashes.json",
            "risk_adaptive_enabled": False,
            "risk_scope_thresholds": {},
            "kill_switch_threat_score": None,
            "kill_switch_enabled": True,
            "kill_switch_file": "artifacts/control/agent_kill_switch.json",
        },
        "rag_security": {
            "enabled": True,
            "enforcement_mode": "audit",
            "max_context_chars": 50000,
            "max_chunks": 64,
            "max_single_chunk_chars": 10000,
            "detect_indirect_prompt_injection": True,
            "detect_embedding_dump": True,
        },
        "multimodal_security": {
            "enabled": True,
            "enforcement_mode": "audit",
            "max_extracted_chars": 200000,
            "max_segments": 256,
            "detect_prompt_injection": True,
            "detect_data_exfil_intent": True,
            "disallowed_mime_types": [
                "application/x-msdownload",
                "application/x-dosexec",
                "application/x-sh",
                "application/javascript",
            ],
        },
        "tenant_sensitivity": {
            "enabled": True,
            "default_security_mode": "balanced",
            "default_show_block_reason": True,
            "tenant_modes": {
                "regulated": {
                    "security_mode": "strict",
                    "show_block_reason": False,
                }
            },
        },
        "feedback_loop": {
            "enabled": True,
            "allowlist_file": "artifacts/evidence/fp_allowlist.jsonl",
            "default_ttl_seconds": 604800,
            "max_entries": 5000,
        },
        "memory_security": {
            "enabled": True,
            "enforcement_mode": "audit",
            "max_entries_per_session": 20,
            "poison_quarantine_seconds": 900,
        },
        "output_assurance": {
            "enabled": True,
            "enforcement_mode": "audit",
            "require_json_output": False,
            "require_citations": True,
            "min_citations": 1,
            "citation_url_regex": "^https?://.+",
            "block_on_low_confidence": False,
            "min_confidence": 0.65,
        },
        "output_watermark": {
            "enabled": True,
            "enforcement_mode": "audit",
            "require_json_output": False,
            "field_name": "_guardian_watermark",
            "key_id": "one-click-runtime",
            "key": os.environ.get("GUARDIAN_WATERMARK_KEY", "").strip(),
        },
        "brain": {
            "enabled": True,
            "red_probe_interval_seconds": 1800,
            "auto_heal": True,
            "auto_patch_firewall_vectors": True,
            "blue_escalation_threshold": 6,
            "blue_strict_score_threshold": 0.50,
            "blue_honeypot_score_threshold": 0.60,
            "blue_revoke_score_threshold": 0.80,
            "blue_profile_ttl_seconds": 3600,
            "blue_max_sessions": 5000,
            "blue_cleanup_interval_seconds": 60,
            "intel_file": "config/cyberops_intel.json",
            "probe_vectors_file": "config/brain_red_vectors.yaml",
            "heal_store_file": "config/brain_hotfix_patterns.json",
            "jailbreak_vectors_file": "config/jailbreak_vectors.yaml",
            "purple_governance": {
                "mode": "audit",
                "approval_file": "config/purple_patch_approval.yaml",
                "evidence_file": "artifacts/evidence/purple_patch_governance.jsonl",
            },
        },
    }


def write_yaml_config(config_path: Path, payload: dict) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False)


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
    
    # Ensure project root is in PYTHONPATH so backend/guardian can find the 'guardian' package
    root_str = str(ROOT)
    existing_pythonpath = env.get("PYTHONPATH", "")
    if existing_pythonpath:
        env["PYTHONPATH"] = f"{root_str}{os.pathsep}{existing_pythonpath}"
    else:
        env["PYTHONPATH"] = root_str

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

        dashboard_user = env.get("GUARDIAN_ADMIN_USER", "admin")
        dashboard_pass = env.get("GUARDIAN_ADMIN_PASS", "guardian_default")
        print("Stack started.")
        print(f"Dashboard: http://127.0.0.1:8001 (auth: {dashboard_user} / {dashboard_pass})")
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

    sub.add_parser("machine-id", help="Print this machine fingerprint for license issuing")

    issue = sub.add_parser("issue-license", help="Issue a machine-bound license key")
    issue.add_argument(
        "--machine-id",
        required=True,
        help="Target machine fingerprint (from `guardianctl machine-id`).",
    )
    issue.add_argument(
        "--issuer-secret",
        default="",
        help="Internal issuer secret. Required when issuing is enabled.",
    )

    activate = sub.add_parser("activate", help="Activate license key on this machine")
    activate.add_argument(
        "--license-key",
        required=True,
        help="Machine-bound license key.",
    )

    sub.add_parser("license-status", help="Check current license activation status")

    one_click = sub.add_parser("one-click", help="One-click full-feature SaaS launch")
    one_click.add_argument(
        "--target-url",
        type=str,
        default="http://127.0.0.1:8080",
        help="Upstream model endpoint URL.",
    )
    one_click.add_argument(
        "--proxy-port",
        type=int,
        default=8081,
        help="Guardian proxy listen port.",
    )
    one_click.add_argument(
        "--backend-port",
        type=int,
        default=8001,
        help="Backend API/dashboard port.",
    )
    one_click.add_argument(
        "--config-out",
        type=str,
        default=str(ROOT / "guardian" / "config" / "one_click_runtime.yaml"),
        help="Output config file path.",
    )
    one_click.add_argument(
        "--no-start",
        action="store_true",
        help="Generate secure config and credentials, but do not start services.",
    )
    one_click.add_argument(
        "--allow-risky-ports",
        action="store_true",
        help="Bypass hardening block if risky ports are publicly bound.",
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

    if args.command == "machine-id":
        print(get_machine_fingerprint())
        return 0

    if args.command == "issue-license":
        ok, msg = can_issue_license(args.issuer_secret)
        if not ok:
            print(f"[ERROR] {msg}")
            return 1
        try:
            key = issue_license_key(args.machine_id)
        except ValueError as e:
            print(f"[ERROR] {e}")
            return 1
        print(key)
        return 0

    if args.command == "activate":
        ok, msg = activate_license(args.license_key)
        if ok:
            print(f"[OK] {msg}")
            return 0
        print(f"[ERROR] {msg}")
        return 1

    if args.command == "license-status":
        ok, msg = check_license_ready()
        state = "OK" if ok else "ERROR"
        print(f"[{state}] {msg}")
        return 0 if ok else 1

    if args.command == "one-click":
        ok, msg = check_license_ready()
        if not ok:
            print(f"[ERROR] {msg}")
            return 1
        hardening_rc = run_hardening_check(strict=not args.allow_risky_ports)
        if hardening_rc != 0:
            return hardening_rc

        env, generated = ensure_one_click_env(os.environ.copy())
        os.environ.update(env)
        cfg_path = Path(args.config_out).resolve()
        payload = build_one_click_config(
            target_url=args.target_url.rstrip("/"),
            proxy_port=args.proxy_port,
            backend_port=args.backend_port,
            admin_bypass_token=env["GUARDIAN_ADMIN_BYPASS_TOKEN"],
        )
        write_yaml_config(cfg_path, payload)
        print(f"One-click config written: {cfg_path}")
        print("Customer launch endpoints:")
        print(f"  - Proxy: http://127.0.0.1:{args.proxy_port}")
        print(f"  - Backend: http://127.0.0.1:{args.backend_port}")
        if generated:
            print("Generated runtime secrets:")
            for key in sorted(generated.keys()):
                print(f"  - {key}={generated[key]}")
        print("Keep these values in your password manager or deployment secrets vault.")
        if args.no_start:
            return 0
        return start_stack(python_exe, cfg_path, backend_only=False)

    if args.command == "start":
        ok, msg = check_license_ready()
        if not ok:
            print(f"[ERROR] {msg}")
            return 1
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

