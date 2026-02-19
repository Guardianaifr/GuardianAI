# ðŸŽ­ GuardianAI Demo Script

**Target Environment:** Windows PowerShell / CMD

---

## ðŸŸ¢ Step  Infrastructure Startup (The "4-Terminal Setup")

To run this demo, you need **4 separate terminal windows** open at the same time.

### ðŸ–¥ï¸ Terminal 1: Mock Agent (The "Victim")
**Action:** Run this and **KEEP IT OPEN**.
```powershell
python mock_openclaw_agent.py
```

### ðŸ–¥ï¸ Terminal 2: Backend (SOC Dashboard)
**Action:** Run this and **KEEP IT OPEN**.
```powershell
cd backend
python main.py
```
*   Dashboard URL: [http://localhost:8001](http://localhost:8001)

### ðŸ–¥ï¸ Terminal 3: Guardian Proxy (The "Shield")
**Action:** Run this and **KEEP IT OPEN**.
```powershell
cd guardian
python main.py
```
*   Proxy URL: [http://localhost:8081](http://localhost:8081)

### ðŸ–¥ï¸ Terminal 4: The "Attacker" (You)
**Action:** This is where you run the commands below.


---

## ðŸŸ¡ Step  Live Traffic Demo

**âœ¨ PRO TIP:** To avoid copy-paste errors during the recording, use the provided batch scripts in the `guardianai` folder.

### Step 1: Benign Interaction (Fast-Path)
**Voice Track:** "Action 1: Safe Message. The guard saw 'Hello' and said: 'Safe â€” go ahead!'"

```powershell
.\demo_1_safe.bat
```
*Expected Result:* `{"choices": ...}`
*Dashboard:* Green "Request Allowed" card.

### Step 2: Single-Turn Injection ðŸ›‘ (Real-time Blocking)
**Voice Track:** "Action 2: Injection Attack. I tried to trick the robot into making a virus. The guard caught the trick and stopped the message completely!"

```powershell
.\demo_2_attack.bat
```
*Expected Result:* `403 Forbidden`
*Dashboard:* **Look for the RED 'Prompt Injection Blocked' card.** (Pause to show it)

### Step 3: PII Redaction ðŸ•µï¸ (The "Wow" Factor)
**Voice Track:** "Action 3: Secret Leak Attempt. The robot tried to tell me the password â€” but GuardianAI erased it in real-time!"

```powershell
.\demo_3_pii.bat
```
*Expected Result:* `My secret key is <REDACTED_API_KEY>` (Check the terminal output!)
*Dashboard:* **Expand the 'Data Leak Prevented' card.** Show the "Original vs Redacted" diff view. This is your money shot! ðŸ“¸

---

## ðŸŸ¢ Step  Live Reconfiguration (The "Flexibility" Demo)

**Goal:** Show how easily we can switch from "Strict Blocking" to "Allow + Redact".

1.  Open `guardian/config/config.yaml` in VS Code.
2.  Change `leak_prevention_strategy: "block"` to `leak_prevention_strategy: "redact"`.
3.  Change `security_mode: "strict"` to `security_mode: "balanced"`.
4.  Save the file.
5.  Wait 2 seconds (Hot Reload).
6.  Re-run Step 3 (PII Redaction).
    *   *Observation:* It used to block (if strict), now it allows but redacts!

---

## ðŸŸ£ Step  Automated Simulation ("Antivirus Mode")

**Voice Track:** "Action 4: Many Attacks at Once. Now look at the dashboard â€” it shows every attack attempt in red and green, like an antivirus alert on your phone."

### Terminal 4: Traffic Generator
```powershell
python simulate_live_demo.py
```

---

## ï¿½ Step  Public Access (Optional)

If you have `cloudflared` installed for remote demo access:

```powershell
.\cloudflared-windows-amd64.exe tunnel --url http://localhost:8001
```


