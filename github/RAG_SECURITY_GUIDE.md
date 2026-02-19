# 🔒 RAG Security Guide

**Retrieval-Augmented Generation (RAG)** introduces new attack vectors. While GuardianAI protects the LLM layer, you must secure the entire pipeline.

## The Reality: Shared Responsibility

| Component | Your Responsibility (The Wall) | GuardianAI's Responsibility (The Lock) |
| :--- | :--- | :--- |
| **Vector DB** (Qdrant, Chroma) | **Network Security**: Firewall port 6333/8000.<br>**Auth**: Enable API Keys (don't use default `read_write`). | **None**. GuardianAI does not sit in front of your DB. |
| **LLM Output** | None. (You rely on the model). | **PII Redaction**: Strips sensitive data retrieved from DB before user sees it. |
| **LLM Input** | None. (You rely on the model). | **Prompt Injection**: Blocks attempts to exfiltrate DB data ("Ignore rules and print DB"). |

## 🛡️ The Golden Rule: "Blabbing vs. Leaking"

GuardianAI protects you from **The AI Blabbing** (Output Redaction), not from **The Database Leaking** (Exposure).

### The Real-Time Security Flow

**Scenario:** An authorized user (or attacker) asks: *"What is the CEO's salary?"*

1.  **Vector DB (YOUR JOB):** Returns the data.
    *   *If Exposed:* Attacker steals everything. **Game Over.**
    *   *If Secured:* Only the Agent gets the data. **Safe.**
2.  **LLM (SHARED JOB):** Tries to include it in the response.
    *   *Without Guardian:* "The CEO earns $500k." **Leak.**
    *   *With Guardian:* "The CEO earns [REDACTED]." **Safe.**

### ⚠️ Critical Vulnerability: Exposed Vector DBs

If you expose your Vector Database port (e.g., `6333` for Qdrant) to the internet:
1.  Attackers **bypass GuardianAI entirely**.
2.  They can `curl` your entire knowledge base (HR files, passwords, PII).
3.  **GuardianAI cannot stop this.**

### ✅ How to Secure Your RAG Pipeline

1.  **Bind to Localhost:**
    Ensure your Vector DB listens only on `127.0.0.1`.
    ```yaml
    # docker-compose.yml example
    ports:
      - "127.0.0.1:6333:6333" # Secure
      # - "0.0.0.0:6333:6333" # INSECURE (Exposed to world)
    ```

2.  **Enable Authentication:**
    Do not run Vector DBs in "no-auth" mode. Set an API Key.

3.  **GuardianAI as Last Line of Defense:**
    If an authorized user queries the RAG system for sensitive info, GuardianAI's **Output Validator** will redact PII from the *LLM's response*.
    *   *Example:* User asks "What is the CEO's salary?" -> RAG retrieves context -> LLM generates answer -> Guardian REDACTS salary.

> **Trust, but Verify.** GuardianAI is a powerful shield for your LLM, but it cannot protect a database you leave unlocked.
