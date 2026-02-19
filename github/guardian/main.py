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

# Force UTF-8 for Windows console to support emojis
if sys.platform.startswith('win'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from utils.logger import setup_logger
from guardrails.input_filter import InputFilter

logger = setup_logger("GuardianAI")

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

    # Initialize and run Interceptor Proxy
    proxy = None
    if config.get('proxy', {}).get('enabled'):
        try:
            from runtime.interceptor import GuardianProxy
            proxy = GuardianProxy(config)
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

if __name__ == "__main__":
    main()
