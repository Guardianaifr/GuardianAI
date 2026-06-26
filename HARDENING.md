# GuardianAI Security Hardening Guide

Follow these practices to secure your GuardianAI deployment against advanced threats.

## 1. Secret Management

### Do Not Hardcode
- Never store API keys or backend tokens in `config.yaml`.
- Use **Environment Variables** for all secrets.

### Supported Secrets
- `GUARDIAN_OPENROUTER_API_KEY`: For AI Firewall model calls.
- `GUARDIAN_BACKEND_TOKEN`: For authenticated telemetry reporting.

## 2. Network Security

### Ingress Filtering
- The Guardian Proxy should **NOT** be exposed directly to the public internet without a Load Balancer or WAF.
- Use TLS 1.3 for all incoming connections.

### Egress Filtering
- Limit Guardian Proxy egress to:
  - Valid downstream agent URLs.
  - Known AI provider APIs (e.g., `openrouter.ai`).
  - Community threat feed URLs.
  
  ### Base64 Evasion Prevention
  - Ensure `enable_base64_detection` is set to `true` (Segment 4 requirement).
  - This blocks obfuscated payloads with high entropy (potential command-and-control communication).

## 3. Defensive Configuration (config.yaml)

### Security Mode
- **Strict**: Recommended for financial or healthcare applications. Blocks on any ambiguity.
- **Balanced**: Best for general productivity. Minimal false positives.

### Data Leak Prevention
- Ensure `leak_prevention_strategy` is set to `block` in high-security environments.
- Use `redact` only for development or non-critical paths.

### Distributed Rate Limiting (SaaS)
- For multi-instance deployments, configure Redis-backed token buckets:
  - `rate_limiting.redis_url`
  - `rate_limiting.redis_prefix`
- If Redis is unavailable, GuardianAI safely falls back to in-memory buckets (single-node mode).

## 4. Host Security

### Running as Non-Root
- Always run the Guardian processes as a dedicated `guardian` user with limited shell access.
- In Docker, use: `USER 1000:1000`.

### System Shield (Runtime Monitor)
- Keep `RuntimeMonitor` enabled to detect unauthorized process spawns or resource exhaustion attacks.

## 5. Regular Audits

### Pattern Updates
- Schedule a job to `POST /api/reload-model` weekly to ensure the latest jailbreak vectors are loaded into the AI Firewall.

### Dependency Scanning
- Run `pip-audit` monthly to check for CVEs in libraries like `transformers`, `torch`, or `flask`.

## 6. Policy Governance

- Enable governance gate in `config.yaml`:
  - `governance.enabled: true`
  - `governance.mode: enforce` (or `audit`)
  - `governance.policy_file: config/policy_control.yaml`
- High-risk config relaxations (for example `security_mode: lenient`) require approval metadata:
  - `approval.status: approved`
  - `approval.approver`
  - `approval.ticket`
  - `approval.config_sha256` (integrity pin of the exact config file)
- In `enforce` mode, startup is blocked when policy checks fail.



