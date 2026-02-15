# 📦 Deployment Strategy: "One Click" for Everyone

To make GuardianAI accessible to both "Vibe Coders" (Desktop Users) and "DevOps Engineers" (Cloud Users), we will implement a dual-track deployment strategy.

## 1. The "Vibe Coder" Path: Standalone Executable
**Goal:** Zero dependencies. No Python, no Pip, no terminal. Just double-click.
*   **Technology:** `PyInstaller`
*   **Output:** `GuardianAI.exe` (Windows) / `GuardianAI` (Linux/Mac)
*   **Experience:**
    1.  User downloads `GuardianAI.zip`.
    2.  User extracts and double-clicks `GuardianAI.exe`.
    3.  The "Setup Wizard" launches automatically in a window.
    4.  System Tray icon appears.

## 2. The "DevOps" Path: Docker Container
**Goal:** Standard, reproducible, cloud-agnostic deployment.
*   **Technology:** `Docker` & `Docker Compose`
*   **Output:** `guardianai:latest` image.
*   **Experience:**
    1.  User runs `docker-compose up -d`.
    2.  GuardianAI starts on port 8081.
    3.  Dashboard starts on port 8501.
    4.  Environment variables handle config (`GUARDIAN_ADMIN_PASS=...`).

---

## 3. The "Private Cloud" Path: Railway
**Goal:** One-click deployment to a private server.
*   **Technology:** `Dockerfile` + `railway.json`
*   **How to Deploy (Step-by-Step):**

    **Phase 1: Put Code on GitHub (Private)**
    1.  Go to [GitHub.com](https://github.com/new) and create a **New Repository**.
    2.  Select **Private**.
    3.  Push your code:
        ```bash
        git init
        git add .
        git commit -m "Initial commit"
        git branch -M main
        git remote add origin https://github.com/YOUR_USER/YOUR_REPO.git
        git push -u origin main
        ```

    **Phase 2: Connect Railway**
    1.  Go to [Railway.app](https://railway.app) and Login with GitHub.
    2.  Click **New Project** > **Deploy from GitHub repo**.
    3.  Select your new **Private Repo**.
    4.  Railway will see `railway.json` and ask: *"What is GUARDIAN_ADMIN_PASS?"*
    5.  Enter your password (e.g., `SuperSecretPass123`).
    6.  Click **Deploy**.

    **Result:**
    *   Railway builds your Docker image privately.
    *   It gives you a URL (e.g., `https://guardian-production.up.railway.app`).
    *   **Done.** 🚀

---

## 📅 Implementation Plan (Phase 5)

### Step 1: Dockerize (Priority: High) - ✅ COMPLETE
*   [x] Create `Dockerfile` (optimized python:3.9-slim).
*   [x] Create `docker-compose.yml` (orchestrates Guardian + Dashboard).
*   [x] Create `railway.json` for One-Click Cloud Deploy.

### Step 2: Build Executable (Priority: User Request)
*   Create `guardian.spec` for PyInstaller.
*   Bundle `presidio` dependencies (spacy models need special handling).
*   Build and Test on Windows.

### Step 3: "One-Click" Script
*   `install.bat`: Checks for Docker. If present, runs Docker. If not, asks to download Exe.

---

## ❓ Decision Required
We will implement **BOTH** to cover 100% of the market.
*   **Servers** need Docker.
*   **People** need Exes.
