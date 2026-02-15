import os
import sys
import yaml
import time

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("========================================================")
    print("   🛡️  GuardianAI - Setup Wizard")
    print("========================================================")
    print("")

def get_input(prompt, default=None):
    if default:
        user_input = input(f"{prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()

def get_bool(prompt, default="y"):
    while True:
        val = get_input(f"{prompt} (y/n)", default).lower()
        if val in ['y', 'yes']:
            return True
        elif val in ['n', 'no']:
            return False

def main():
    clear_screen()
    print_header()
    print("Welcome! Let's configure your AI Shield.")
    print("")

    # 1. Choose Target
    print("--- [1] Target Selection ---")
    print("Which AI service do you want to protect?")
    print("1. Ollama (Local)")
    print("2. Anthropic Claude (Cloud)")
    print("3. OpenAI / Codex (Cloud)")
    print("4. Custom URL")
    
    choice = get_input("Select number", "1")
    
    target_url = "http://localhost:11434"
    port = 8082
    upstream_key = None
    service_name = "Ollama"

    if choice == "2":
        target_url = "https://api.anthropic.com"
        port = 8083
        service_name = "Claude"
        upstream_key = get_input("Enter your Anthropic API Key (sk-...) [Leave empty to use client key]")
    elif choice == "3":
        target_url = "https://api.openai.com"
        port = 8084
        service_name = "OpenAI"
        upstream_key = get_input("Enter your OpenAI API Key (sk-...) [Leave empty to use client key]")
    elif choice == "4":
        target_url = get_input("Enter target URL (e.g., http://localhost:5000)")
        port = int(get_input("Enter local listen port", "8080"))
        service_name = "Custom"
    
    print(f"\n✅ Selected: {service_name} (Target: {target_url}) -> Proxy Port: {port}")
    
    print("\n--- [2] Security Features ---")
    
    # 2.1 Core Features
    enable_pii = get_bool("Enable PII Redaction (Hide Phone/CC/Email)?")
    leak_strategy = "block"
    if enable_pii:
        print("  - Strategy: [1] Redact (Replace with asterisks) [2] Block (Stop response entirely)")
        ls_choice = get_input("  Choice", "1")
        leak_strategy = "green" if ls_choice == "1" else "block"
        if ls_choice == "1": leak_strategy = "redact" # Fix variable naming consistency

    enable_injection = get_bool("Enable Prompt Injection Blocking?")
    security_mode = "balanced"
    if enable_injection:
        print("  - Level: [1] Balanced (Recommended) [2] Strict (Paranoid)")
        mode_choice = get_input("  Choice", "1")
        security_mode = "strict" if mode_choice == "2" else "balanced"

    enable_ratelimit = get_bool("Enable Rate Limiting (Prevent Spam)?")
    enable_threatfeed = get_bool("Enable Community Threat Feed (Block known attacks)?")
    enable_monitor = get_bool("Enable Runtime Process Monitor (Block netcat/powershell)?")

    # 2.2 Admin Access
    print("\n--- [3] Access Control ---")
    admin_token = get_input("Set an Admin/Bypass Token (Password for high-privilege actions)", "s3cr3t_admin_key_123")

    # Generate Config
    config = {
        "app_name": f"GuardianAI [{service_name}]",
        "version": "2.0.0",
        "guardian_id": f"shield-{service_name.lower()}-wizard",
        "proxy": {
            "enabled": True,
            "listen_port": port,
            "target_url": target_url
        },
        "security_policies": {
            "block_prompt_injection": enable_injection,
            "validate_output": enable_pii,
            "security_mode": security_mode,
            "show_block_reason": True,
            "leak_prevention_strategy": leak_strategy,
            "admin_token": admin_token
        },
        "rate_limiting": {
            "enabled": enable_ratelimit,
            "requests_per_minute": 60
        },
        "backend": {
            "enabled": True, # Always enable telemetry for the dashboard
            "url": "http://127.0.0.1:8001/api/v1/telemetry"
        },
        "scanner": {
            "skills_directory": "./skills",
            "blocked_imports": ["os", "subprocess"],
            "blocked_functions": ["eval", "exec"]
        },
        "runtime_monitoring": {
            "enabled": enable_monitor,
            "blocked_processes": ["nc.exe", "ncat.exe", "powershell.exe", "calc.exe"], # Added calc for demo
             "max_cpu_percent": 95.0,
            "max_memory_percent": 90.0,
            "check_interval_seconds": 5
        },
        "threat_feed": {
            "enabled": enable_threatfeed,
             "url": "https://raw.githubusercontent.com/guardianai/threat-feed/main/patterns.json", # Placeholder
             "update_interval_seconds": 3600
        }
    }

    if upstream_key:
        config['proxy']['upstream_key'] = upstream_key

    # Save Config
    config_dir = os.path.join(os.path.dirname(__file__), "config")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "wizard_config.yaml")
    
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print("\n--- [4] Ready to Launch ---")
    print(f"Configuration saved to: {config_path}")
    print(f"Starting GuardianAI on PORT {port}...")
    print("Press Ctrl+C to stop.")
    time.sleep(2)
    
    # Set Env Var and Run Main
    os.environ['GUARDIAN_CONFIG'] = config_path
    
    # We import main here to run it in the same process
    try:
        from main import main as guardian_main
        guardian_main()
    except ImportError:
        # Fallback if running from root
        sys.path.append(os.path.join(os.getcwd(), 'guardian'))
        from guardian.main import main as guardian_main
        guardian_main()

if __name__ == "__main__":
    main()
