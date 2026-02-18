## GuardianAI

**AI security proxy** that protects LLM applications from prompt injection, jailbreaks, and data leakage.

[![Tests](https://img.shields.io/badge/tests-110%2F110%20passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-80%25-yellow)]()


---

## Quick Start (Windows)

We've made it easy. Just use our unified launcher:

1.  **Double-click** `start_guardian.bat`.
2.  Select **Option 2** (Config Wizard) to set up your shield.
3.  Select **Option 1** (Start Shield) to protect your AI.
4.  Select **Option 3** (Launch Dashboard) to view live threats.

### Validation Demos

We include 6 ready-to-run scenarios to prove the security works:

| Script | Description |
| :--- | :--- |
| `demo_1_safe.bat` | Sends a normal request (Fast-Path verify) |
| `demo_2_injection.bat` | Simulates a jailbreak attack (Blocked) |
| `demo_3_pii.bat` | Asks for sensitive data (Redacted) |
| `demo_4_admin_bypass.bat` | Tests Admin Token access control |
| `demo_5_rogue_process.bat` | Spawns `calc.exe` to test Runtime Monitor |
| `demo_6_rate_limit.bat` | Floods the API to test DoS protection |

---

## Manual Launch
1.  **Multi-turn Context:** Currently analyzes strictly on a per-request basis. Does not yet maintain a sliding window of conversation history for context-aware verification.
2.  **Rate Limiting:** Per-user, per-key, telemetry, and auth endpoint limits are implemented in the backend.
3.  **Authentication:** Backend supports JWT bearer auth (with revocation) and Basic fallback for compatibility.

## Backend Hardening (Implemented)
1. JWT issuance, verification, and revocation (`/api/v1/auth/token`, `/api/v1/auth/revoke`).
2. Managed API keys for telemetry (`create/list/revoke/rotate`).
3. Per-user and per-key rate-limit overrides.
4. HTTPS enforcement and optional TLS cert/key startup.
5. Prometheus-style metrics endpoint (`/metrics`) and component-aware health endpoint (`/health`).
6. External audit forwarding (HTTP + Syslog) with strict mode and retry queue.
6.1 Optional enterprise sink adapters: Splunk HEC and Datadog Logs.
7. Tamper-evident audit hash chain with verification endpoint (`/api/v1/audit-log/verify`).
8. Role-based endpoint access control (`admin`/`auditor`/`user`) for least-privilege operations.
9. Optional Redis-backed distributed rate limiting for multi-instance deployments.

## Production Hardening (CRITICAL)

**The Reality: GuardianAI is a Lock, Not a Wall.**

Just like a lock doesn't help if you leave the door open, GuardianAI cannot protect you if you expose your LLM insecurely.

**DO NOT:**
*   Expose your LLM port (e.g., 8080/11434) directly to the internet.
*   Rely on GuardianAI as your *only* line of defense.

**DO:**
1.  **Network Security (The Foundation):**
    *   Bind your LLM to `127.0.0.1` (Localhost only).
    *   Use a **Firewall** (UFW/AWS Security Groups) to block all external traffic to ports 8080/11434.
    *   Access remotely via **VPN** or **SSH Tunnel** whenever possible.

2.  **GuardianAI (The Defense Layer):**
    *   If you *must* expose an endpoint, expose **only port 8081** (Guardian).
    *   GuardianAI adds **Rate Limiting, Audit Logging, and PII Redaction** to traffic you have *deliberately* decided to allow.
    *   It protects against application-level attacks:
        *   **Prompt Injection** (Jailbreaks)
        *   **PII Leaks** (Keys, Phone Numbers)
        *   **Output Redaction for RAG** (Prevents sensitive retrieval data from leaking via LLM)
        *   **Rogue Processes** (Reverse Shells)
        *   **Unauthorized Access** (No more open ports!)

> **In Short:** GuardianAI protects you from **The AI Blabbing**, not from **The Database Leaking**. 
> It is the *Lock* on the door, but you must build the *Wall* (Network Security).
    *   **CRITICAL LIMITATION:** GuardianAI protects the *LLM Output*. It does **NOT** protect your Vector Database (Qdrant/Chroma) if you expose it to the internet! Secure your DB ports.
    *   See [RAG_SECURITY_GUIDE.md](RAG_SECURITY_GUIDE.md) for DBs.
    *   See [REMOTE_ACCESS_GUIDE.md](REMOTE_ACCESS_GUIDE.md) for ComfyUI/Remote GPUs.

3.  **Secrets Management:**
    *   GuardianAI never returns your upstream API keys to the client.
    *   However, if an attacker gains Admin access (via weak token), they can reconfigure the system. **Set a strong ADMIN_TOKEN.**

---

##  Contributing
...

##  Installation

### Option 0: One-Command Installer (Windows/macOS/Linux)
```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

```bash
# macOS / Linux
./install.sh
```

After install:
```bash
python guardianctl.py setup
python guardianctl.py start
```

### Option 1: Docker / Cloud Deployment (Preferred for Servers)
**Private Cloud (One Click):**

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https%3A%2F%2Fgithub.com%2Fguardianai%2Fguardian&envs=GUARDIAN_ADMIN_PASS,PORT,LOG_LEVEL)

**Manual Docker:**
Run GuardianAI + Dashboard in one command:
```bash
docker-compose up -d
```
*   **Guardian AI Proxy:** `http://localhost:8081`
*   **Dashboard:** `http://localhost:8501`

### Option 2: One-Click Executable (Preferred for Desktop)
Zero dependencies. Double-click to run.

1.  **Build the Exe (First Time Only):**
    ```cmd
    build_exe.bat
    ```
    *(Creates `dist\GuardianAI\GuardianAI.exe`)*

2.  **Run:**
    Double-click `GuardianAI.exe`.
    *   It launches the **Dashboard** and **Proxy** automatically.
    *   No Python or Docker required!

### Option 3: Manual Installation (Python)
1.  **Clone the Repo:**
    ```bash
    git clone https://github.com/guardianai/guardian.git
    cd guardian
    ```
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    python -m spacy download en_core_web_lg
    ```
3.  **Launch:**
    ```cmd
    start_guardian.bat
    ```

**That's it!** Your LLM is now protected.

---

##  What It Does

GuardianAI sits between your application and your LLM, providing:

### Input Protection
-  **Jailbreak Detection** - Blocks prompt injection attempts
-  **Command Injection** - Prevents OS command execution
-  **Role Manipulation** - Stops "ignore instructions" attacks

### Output Protection
-  **PII Redaction** - Removes emails, SSNs, credit cards, API keys
-  **Data Leakage Prevention** - Blocks sensitive information exposure

### Advanced Security
-  **AI Firewall** - Semantic analysis of prompts
-  **Rate Limiting** - Prevents abuse
-  **Threat Intelligence** - Real-time threat feed integration
-  **Process Monitoring** - Detects malicious process spawning

---

##  Performance & Security

### Latency & Throughput
- **Latency:** **12ms p95** (Full interception overhead) 
- **Throughput:** 1000+ requests/second

### Security Metrics (Balanced Mode Validation)
- **Recall:** **100%** (Detected all 500 jailbreak attempts)
- **Precision:** **94.52%** (29 false positives on 1000 benign inputs)
- **F1-Score:** **0.9718** (Excellent balance)
- **Test Corpus:** 1500 prompts (1000 benign, 500 malicious)

See [VALIDATION.md](VALIDATION.md) for detailed breakdown by security mode.

---

##  Architecture

```
            
 Your App      GuardianAI     LLM   
 (Client)             (Proxy)           (Agent) 
            
                            
                            
                     
                       Security    
                       Dashboard   
                     
```

**Components:**
- **Interceptor** - HTTP proxy (Flask)
- **Input Filter** - Regex-based pattern matching
- **AI Firewall** - Semantic analysis (embeddings)
- **Output Validator** - PII detection (Presidio)
- **Monitor** - Process and resource tracking

---

##  Documentation

- **[API Reference](API.md)** - Endpoints, configuration, examples
- **[Deployment Guide](DEPLOYMENT.md)** - Setup, configuration, production tips
- **[Operations Guide](OPERATIONS.md)** - State management, TTL, and backup procedures
- **[Hardening Guide](HARDENING.md)** - Security best practices and remediation
- **[Roadmap](ROADMAP.md)** - Development roadmap

---

##  Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest --cov=guardian --cov-report=term-missing tests/

# Run specific test
python -m pytest tests/guardrails/test_input_filter.py -v
```

**Current Status:** 110/110 tests passing.

---

##  Configuration

Create `config.yaml`:

```yaml
proxy:
  listen_port: 8080
  target_url: "http://localhost:18789"

security:
  mode: "balanced"  # strict | balanced | permissive
  enable_ai_firewall: true
  enable_pii_redaction: true
  
monitoring:
  enable_dashboard: true
  dashboard_port: 5000
```

---

##  Development

```bash
# Install dev dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v

# Run with auto-reload
python guardian/main.py --reload

# View logs
tail -f guardian.log
```

---

##  Roadmap

- [x] Core security features
- [x] Testing infrastructure (92 tests)
- [x] Code quality improvements
- [x] Expand test coverage to 64%
- [x] Add comprehensive documentation (Ops/Hardening)
- [x] Performance optimizations (p95: 12ms)
- [x] Production deployment guide

---

##  Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

---

##  License

[Add your license here]

---

##  Support

- **Issues:** [GitHub Issues](link)
- **Docs:** [Full Documentation](link)
- **Email:** support@guardianai.com

---

**Built with  for AI security**
"# Guardian-private" 






