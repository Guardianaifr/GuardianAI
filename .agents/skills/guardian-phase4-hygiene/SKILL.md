---
name: guardian-phase4-hygiene
description: >-
  Untracks all scratch .db files from git (not deleted from disk),
  untracks all tools/_*.txt debug output files from git,
  untracks root-level .png and payload.json from git,
  updates .gitignore to prevent re-tracking of above,
  updates .dockerignore to exclude tests/, tools/, contracts/, htmlcov/,
  pins web3 and eth-account to exact versions in requirements.txt,
  moves pytest/pytest-cov/pytest-asyncio to requirements-dev.txt,
  commits in two clean separate commits with audit trail messages,
  and assesses git history for secrets.
---

# Guardian Phase 4: Repository Hygiene

## Overview
This skill implements Phase 4 of the GuardianAI Security Audit Remediation. It covers repository cleaning, ignoring scratch data, dependency pinning, and Dockerignore optimizations.

## Workflow

### 1. Untrack Scratched and Debug Files
- Run `git rm --cached` on the following target categories:
  - Scratch databases: `tools/_auth_test_scratch/`, `tools/_auth_unseen_scratch/`
  - Debug and logs: `tools/_*.txt` (e.g. `_debug.txt`, `_final_out.txt`, etc.) and specific others like `tools/rl_out.txt`, `tools/unseen_results.txt`.
  - Root clutter: Root level `.png` files (e.g. `ChatGPT Image ...`) and `payload.json`.

### 2. Update Gitignore & Dockerignore Configs
- **.gitignore:**
  - Block databases: `*.db`
  - Block debug text files: `tools/_*.txt`, `tools/_*_scratch/`, `tools/rl_out.txt`, `tools/rl_output.txt`, `tools/unseen_results.txt`.
  - Block root-level images: `/*.png` (allowing `frontend/public/*.png` specifically).
  - Block build files: `htmlcov/`, `*.spec`, `demo.mp4`, `scratch/`.
- **.dockerignore:**
  - Append patterns to exclude large directories: `tests/`, `tools/`, `contracts/`, `htmlcov/`, `*.md`, `scratch/`, `demo.mp4`, `*.png`, `*.spec` (keeping `README.md` and `../../../docs/architecture/DEPLOYMENT.md`).

### 3. Dependency Hardening
- Pin `web3` and `eth-account` to their exact installed versions in `requirements.txt`.
- Remove dev-only dependencies (`pytest`, `pytest-cov`) from `requirements.txt`.
- Create `requirements-dev.txt` listing `pytest`, `pytest-cov`, and `pytest-asyncio`.

### 4. Git Commit Structure
- Create two clean, separate commits:
  1. Commit 1: Untrack scratch/debug files, `.gitignore`, `.dockerignore`.
  2. Commit 2: Pinned dependencies (`requirements.txt`, `requirements-dev.txt`).

## Acceptance Criteria
- Running `git ls-files` returns nothing for the removed scratch/debug files.
- pytest passes with 0 failures:
  ```powershell
  pytest tests/ -v --ignore=tests/backend/test_billing_checkout.py --ignore=tests/backend/test_customer_billing_storage.py --ignore=tests/security/test_hardened_security_audit.py
  ```
