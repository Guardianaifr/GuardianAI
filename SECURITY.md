# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest `main` | :white_check_mark: |
| older snapshots | :x:          |

The smart contracts are deployed on **Monad testnet only** and have not been audited by a third party.

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
*   **Agent payments:** The relay's approval logic (`/api/v1/attest`), the `GuardianAgentWallet` / `GuardianPolicyGuard` contracts, the Chainlink CRE threat oracle and the agent-card (passkey) checks: anything that lets an agent move funds without a valid GuardianAI approval, or lets one agent spend another's funds.

### Out of Scope (What you must secure yourself)
*   **Network Security:** You must use firewalls/VPNs to protect the underlying server.
*   **Physical Security:** We cannot prevent access if an attacker has physical access to the machine.
*   **Social Engineering:** We cannot prevent authorized users from being tricked.
*   **Model Theft:** We do not DRM model weights.
*   **Owner override:** `GuardianAgentWallet.ownerExecute` bypasses GuardianAI by design (recovery path); protect the owner key.
*   **Known limitations** listed in [metropolis/README.md §6](metropolis/README.md#6-known-limitations-updated-oct-13).

For more details on securing your deployment, please read our [Hardening Guide](docs/architecture/HARDENING.md).

