import multiprocessing
import sys
import os
import time
import subprocess
from pathlib import Path

# Needed for PyInstaller to handle multiprocessing correctly (even if not used extensively now)
multiprocessing.freeze_support()

def run_backend():
    """Runs the FastAPI Backend (GuardianAI Proxy + Dashboard)"""
    import uvicorn
    # Import the app object from backend.main
    sys.path.append(os.getcwd())
    
    # Set environment variables for default config if not present
    os.environ["GUARDIAN_ADMIN_PASS"] = os.environ.get("GUARDIAN_ADMIN_PASS", "guardian_default")
    
    print("ðŸš€ Starting GuardianAI Backend on port 8081...")
    # Note: backend.main serves the SOC dashboard on the root path (/)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8081, log_level="info")

if __name__ == "__main__":
    print("ðŸ›¡ï¸  GuardianAI Launcher")
    print("=========================")
    
    # Run the backend in a single process for simplicity in the frozen exe
    # Since we removed Streamlit, we don't need complex process management here.
    try:
        run_backend()
    except KeyboardInterrupt:
        print("\nStopping GuardianAI...")
    except Exception as e:
        print(f"\n[ERROR] GuardianAI failed to start: {e}")
        input("Press Enter to exit...")

