import multiprocessing
import sys
import os
import time
import subprocess
from pathlib import Path

# Needed for PyInstaller to handle multiprocessing correctly
multiprocessing.freeze_support()

def run_backend():
    """Runs the FastAPI Backend (GuardianAI Proxy)"""
    import uvicorn
    # Import the app object from backend.main
    # Note: We import inside the function to avoid circular imports or side effects
    sys.path.append(os.getcwd())
    
    # We need to set environment variables for default config if not present
    os.environ["GUARDIAN_ADMIN_PASS"] = os.environ.get("GUARDIAN_ADMIN_PASS", "guardian2026")
    
    print("🚀 Starting GuardianAI Backend on port 8081...")
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8081, log_level="info")

def run_dashboard():
    """Runs the Streamlit Dashboard"""
    from streamlit.web import cli as stcli
    
    print("📊 Starting GuardianAI Dashboard on port 8501...")
    
    # Resolve path to dashboard/app.py
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        base_path = sys._MEIPASS
    else:
        # Running as script
        base_path = os.getcwd()
        
    dashboard_script = os.path.join(base_path, "dashboard", "app.py")
    
    # Set arguments for Streamlit
    sys.argv = [
        "streamlit",
        "run",
        dashboard_script,
        "--server.port=8501",
        "--server.address=0.0.0.0",
        "--server.headless=true",
        "--global.developmentMode=false"
    ]
    
    stcli.main()

if __name__ == "__main__":
    print("🛡️  GuardianAI Installer Launcher")
    print("=================================")
    
    # 1. Start Backend Process
    backend_process = multiprocessing.Process(target=run_backend)
    backend_process.start()
    
    # 2. Start Dashboard (in main thread or process)
    # Streamlit needs to be in the main thread usually, or at least a dedicated process
    # We'll run it in a separate process to keep them isolated
    dashboard_process = multiprocessing.Process(target=run_dashboard)
    dashboard_process.start()
    
    print("✅ Services Started.")
    print("   - Backend: http://localhost:8081")
    print("   - Dashboard: http://localhost:8501")
    print("   - Close this window to stop GuardianAI.")
    
    try:
        # Keep main process alive
        while True:
            time.sleep(1)
            if not backend_process.is_alive() or not dashboard_process.is_alive():
                print("⚠️  A service has stopped. Exiting...")
                break
    except KeyboardInterrupt:
        print("\nStopping GuardianAI...")
    finally:
        backend_process.terminate()
        dashboard_process.terminate()
        backend_process.join()
        dashboard_process.join()
