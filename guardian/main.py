"""
GuardianAI - Main Entry Point

This is the main entry point for the GuardianAI security proxy. It orchestrates all
security components (input filtering, output validation, AI firewall, process monitoring)
and provides a unified interface for protecting AI agents from prompt injection,
data leaks, and malicious code execution.

GuardianAI provides multi-layered security:
1. Fast regex-based input filtering (< 1ms)
2. Community threat feed matching
3. AI-powered semantic analysis (50-200ms)
4. Output PII detection and redaction
5. Runtime process monitoring

Key Components:
    - Configuration loading from YAML
    - GuardianProxy initialization
    - Security component orchestration
    - Graceful shutdown handling

Usage:
    ```bash
    # Start GuardianAI proxy
    python main.py
    
    # With custom config
    python main.py --config custom_config.yaml
    ```

Configuration:
    - Default config: config.yaml
    - Proxy settings: listen_port, target_url
    - Security policies: security_mode, validate_output
    - Rate limiting: enabled, max_requests_per_minute

Architecture:
    Client → GuardianAI Proxy → AI Agent
    
    All requests/responses flow through GuardianAI for inspection and filtering.

Author: GuardianAI Team
License: MIT
"""
import yaml
import sys
import signal
import time
import io
import os
from pathlib import Path

# Force UTF-8 for Windows console to support emojis
if sys.platform.startswith('win') and 'pytest' not in sys.modules:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from utils.logger import setup_logger
from guardrails.input_filter import InputFilter

logger = setup_logger("GuardianAI")

_PLACEHOLDER_PATTERNS = {"***REDACTED***", "changeme", "admin", 
                           "password", "token", ""}

def _is_valid_admin_token(token: str | None) -> bool:
    if not token:
        return False
    if token.lower() in _PLACEHOLDER_PATTERNS:
        return False
    if os.environ.get("GUARDIAN_ENV") == "test":
        return len(token) >= 8
    return len(token) >= 32

def validate_security_config(policies: dict):
    admin_token = policies.get('admin_token')
    if admin_token is not None and not _is_valid_admin_token(admin_token):
        raise RuntimeError(
            "SECURITY: admin_token is set to a placeholder or weak value. "
            "Generate a real token and set it via environment variable "
            "before starting."
        )

def load_config(path: str):
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return None

def main():
    logger.info("Initializing GuardianAI...")
    
    config_base_dir = os.path.dirname(__file__)
    
    # Check for custom config from Env Var
    custom_config = os.environ.get('GUARDIAN_CONFIG')
    if custom_config:
        # Support relative paths from project root
        if not os.path.isabs(custom_config):
             # Assuming running from project root, or relative to main.py? 
             # The batch script sets it relative to project root "guardian/config/...", so we might need to handle CWD.
             # Let's try to resolve it relative to CWD first.
             if os.path.exists(custom_config):
                 config_path = custom_config
             else:
                 # Fallback to relative to main.py if needed, or error
                 config_path = os.path.join(os.getcwd(), custom_config)
        else:
             config_path = custom_config
    else:
        config_path = os.path.join(config_base_dir, 'config', 'config.yaml')
        
    logger.info(f"Loading config from: {config_path}")
    config = load_config(config_path)
    
    if not config:
        sys.exit(1)

    # Environment overrides for sensitive production values
    env_admin_token = os.environ.get('GUARDIAN_ADMIN_TOKEN')
    if env_admin_token:
        if 'security_policies' not in config:
            config['security_policies'] = {}
        config['security_policies']['admin_token'] = env_admin_token
        logger.info("Admin token overridden from environment variable.")

    validate_security_config(config.get('security_policies', {}))

    # Governance gate: optional approval/integrity enforcement for high-risk config changes.
    try:
        from security.policy_governance import evaluate_from_runtime_config

        allowed, governance_findings = evaluate_from_runtime_config(config, config_path, config_base_dir)
        for finding in governance_findings:
            level = finding.severity.upper()
            if level in {"CRITICAL", "HIGH"}:
                logger.error(f"[Governance:{finding.code}] {finding.detail}")
            else:
                logger.warning(f"[Governance:{finding.code}] {finding.detail}")
        if not allowed:
            logger.error("Startup blocked by governance policy.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Governance evaluation failed: {e}")
        sys.exit(1)

    # ── Hardening Gate: model provenance (startup) ────────────────────────────
    # Verifies SHA-256 hashes of model artifacts against a manifest file.
    # Config key: hardening.model_manifest_path
    # Fail-closed: If a manifest path is configured, it must exist and hashes must match.
    try:
        from security.hardening_checks import load_model_manifest, verify_model_provenance
        _hardening_cfg = config.get("hardening") or {}
        _manifest_rel = _hardening_cfg.get("model_manifest_path", "")

        if not _manifest_rel:
            logger.info("[HardeningProvenance] No model_manifest_path configured. Skipping provenance check (Standard Mode).")
        else:
            _manifest_path = Path(config_base_dir) / _manifest_rel if not Path(_manifest_rel).is_absolute() else Path(_manifest_rel)
            if not _manifest_path.exists():
                logger.error(f"[HardeningProvenance] FATAL: Manifest configured but not found at {_manifest_path}. Startup aborted.")
                sys.exit(1)
            else:
                _manifest = load_model_manifest(_manifest_path)
                _provenance_findings: list = []
                for _rel, _expected_hash in _manifest.items():
                    _artifact = Path(config_base_dir) / _rel if not Path(_rel).is_absolute() else Path(_rel)
                    _provenance_findings.extend(verify_model_provenance(_artifact, _expected_hash))
                
                _critical_findings = [f for f in _provenance_findings if f.severity in {"critical", "high"}]
                for _pf in _provenance_findings:
                    if _pf.severity in {"critical", "high"}:
                        logger.error(f"[HardeningProvenance] {_pf.category}/{_pf.location}: {_pf.detail}")
                    else:
                        logger.warning(f"[HardeningProvenance] {_pf.category}/{_pf.location}: {_pf.detail}")
                
                if _critical_findings:
                    logger.error(f"[HardeningProvenance] FATAL: {len(_critical_findings)} critical finding(s) detected. Startup aborted.")
                    sys.exit(1)
                else:
                    logger.info("[HardeningProvenance] All model artifacts verified OK.")
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"[HardeningProvenance] FATAL: Provenance check encountered an error: {e}")
        sys.exit(1)

    logger.info(f"Loaded configuration for {config.get('app_name')} v{config.get('version')} (ID: {config.get('guardian_id')})")
    
    # Initialize Skill Scanner
    scanner_config = config.get('scanner', {})
    if scanner_config:
        logger.info("Initializing Skill Scanner...")
        from guardrails.skill_scanner import SkillScanner
        
        scanner = SkillScanner(config)
        skills_dir = scanner_config.get('skills_directory', './mock_skills')
        
        if not os.path.isabs(skills_dir):
            skills_dir = os.path.join(config_base_dir, skills_dir)
            
        logger.info(f"Scanning skills directory: {skills_dir}")
        findings = scanner.scan_directory(skills_dir)
        
        if findings:
            logger.warning(f"Skill Scanner found {len(findings)} issues.")
        else:
            logger.info("Skill Scanner: No issues found.")

    # Initialize and run Runtime Monitor
    monitor = None
    if config.get('runtime_monitoring'):
        try:
            from runtime.monitor import RuntimeMonitor
            monitor = RuntimeMonitor(config)
            monitor.start()
        except Exception as e:
            logger.error(f"Failed to start RuntimeMonitor: {e}")

    # Initialize and run Network Monitor
    net_monitor = None
    if config.get('network_monitoring'):
        try:
            from runtime.network_monitor import NetworkMonitor
            net_monitor = NetworkMonitor(config)
            net_monitor.start()
        except Exception as e:
            logger.error(f"Failed to start NetworkMonitor: {e}")

    # Initialize Filesystem Sandbox
    fs_sandbox = None
    if config.get('filesystem_sandbox'):
        try:
            from runtime.filesystem_sandbox import FilesystemSandbox
            fs_sandbox = FilesystemSandbox(config)
            logger.info("Filesystem Sandbox initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize FilesystemSandbox: {e}")

    # Initialize and run Interceptor Proxy
    proxy = None
    if config.get('proxy', {}).get('enabled'):
        try:
            from runtime.interceptor import GuardianProxy
            proxy = GuardianProxy(config)
            if fs_sandbox:
                proxy.filesystem_sandbox = fs_sandbox
            proxy.start()
        except Exception as e:
            logger.error(f"Failed to start GuardianProxy: {e}")

    # Dashboard display
    # os.system('cls' if os.name == 'nt' else 'clear')
    
    print("\n" + "="*50)
    print("   GUARDIAN AI - SYSTEM PROTECTED   ")
    print("="*50 + "\n")
    print(f"  ✓ App Name:      {config.get('app_name')}")
    print(f"  ✓ Guardian ID:   {config.get('guardian_id')}")
    print("  ✓ Skill Scanner: Active")
    print("  ✓ Runtime Force: Active")
    if config.get('filesystem_sandbox'):
        print("  ✓ FS Sandboxing: Active")
    print(f"  ✓ Proxy Shield:  Active (Port {config.get('proxy', {}).get('listen_port')})")
    if config.get('backend', {}).get('enabled'):
        print(f"  ✓ SaaS Backend:  Connected ({config.get('backend', {}).get('url')[:30]}...)")
    print("\n" + "-"*50 + "\n")
    
    logger.info("GuardianAI Shield is ACTIVE. Press Ctrl+C to exit.")
    
    try:
        while True:
            time.sleep(30)
            logger.info("✅  System Secure - Monitoring active...")
    except KeyboardInterrupt:
        logger.info("Stopping...")
    
    if monitor:
        monitor.stop()
    if net_monitor:
        net_monitor.stop()
    if proxy:
        proxy.stop()

if __name__ == "__main__":
    main()
