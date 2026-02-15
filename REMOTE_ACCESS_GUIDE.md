# 🔒 Secure Remote Access Guide

**The Problem:** You have a powerful GPU server (or Vector DB) running on a remote machine, and you need to access its Web UI (e.g., ComfyUI on port 8188) from your laptop.

**The Mistake:** Running `--listen 0.0.0.0` or opening the port in the firewall.
*   **Result:** The entire internet can see your service.

**The Fix:** **SSH Tunneling (Port Forwarding)**.
*   **Result:** Only YOU can see the service, securely encrypted over SSH.

---

## 🛠️ How to Set Up an SSH Tunnel

### Scenario
*   **Remote Server (GPU):** IP `203.0.113.45` running ComfyUI on `localhost:8188`.
*   **Local Machine (Laptop):** You want to see it at `localhost:8188`.

### Command (Run on your Laptop)
```bash
# Syntax: ssh -L [LocalPort]:localhost:[RemotePort] [User]@[ServerIP]
ssh -L 8188:localhost:8188 user@203.0.113.45
```

### What Happens
1.  Verify the connection is established (Shell opens).
2.  Open your browser on your **Laptop**.
3.  Go to `http://localhost:8188`.
4.  **Magic:** You see the remote ComfyUI!

### Why is this Secure?
1.  **Firewall Closed:** The remote server port 8188 is BLOCKED to the internet.
2.  **Encryption:** All traffic travels through the encrypted SSH connection.
3.  **Authentication:** You must have the SSH Key/Password to connect.

---

## ⚡ Pro Tip: VS Code Tunnels

If you use VS Code, it's even easier:
1.  Connect to the remote server using the **Remote - SSH** extension.
2.  Open the **PORTS** tab (next to Terminal).
3.  Click "Forward a Port" -> Enter `8188`.
4.  VS Code handles the tunnel automatically!

> **Rule of Thumb:** If it doesn't have a login screen (ComfyUI, Qdrant, Ollama), **NEVER** expose it directly. Tunnel it.
