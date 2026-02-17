# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of our software seriously. If you believe you have found a security vulnerability in GuardianAI, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to `security@guardianai.io`.

You can expect:
*   An acknowledgement of your report within 24 hours.
*   A response process for investigation and resolution.
*   Credit for your discovery (if desired).
*   A coordinated disclosure process.

## Security Model

GuardianAI is designed as a **defense-in-depth layer** for LLM applications.

### In Scope (What we protect against)
*   **Prompt Injection:** Attacks attempting to bypass system instructions.
*   **PII Leakage:** Accidental exposure of sensitive data in model responses.
*   **Rate Limiting:** Application-level Denial of Service.
*   **Unauthorized Access:** Protecting the admin interface via authentication.

### Out of Scope (What you must secure yourself)
*   **Network Security:** You must use firewalls/VPNs to protect the underlying server.
*   **Physical Security:** We cannot prevent access if an attacker has physical access to the machine.
*   **Social Engineering:** We cannot prevent authorized users from being tricked.
*   **Model Theft:** We do not DRM model weights.

For more details on securing your deployment, please read our [Hardening Guide](HARDENING.md).

