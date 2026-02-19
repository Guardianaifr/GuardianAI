import os
import hashlib
import time
import subprocess
import psutil
from guardian.runtime.monitor import RuntimeMonitor

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def test_hash_blocking():
    print("Starting Hash-Based Blocking Verification...")
    
    # 1. Use a standard executable (e.g., notepad.exe on Windows)
    target_exe = "C:\\Windows\\System32\\notepad.exe"
    if not os.path.exists(target_exe):
        print("❌ Error: Target executable not found.")
        return

    # 2. Get the hash of the target
    target_hash = get_file_hash(target_exe)
    print(f"Target: {target_exe}")
    print(f"Hash: {target_hash}")

    # 3. Initialize Monitor with the hash blocked
    config = {
        'runtime_monitoring': {
            'enabled': True,
            'check_interval_seconds': 1,
            'blocked_processes': [],
            'blocked_hashes': [target_hash]
        }
    }
    monitor = RuntimeMonitor(config)

    # 4. Start a dummy process (Rename it locally to bypass name-blocking if we had any)
    # Actually, just starting it as is is fine because we only have 'calc.exe' and 'nc.exe' in name blocks.
    print("Spawning process...")
    proc = subprocess.Popen([target_exe])
    pid = proc.pid
    print(f"Spawned PID: {pid}")

    # 5. Run one check cycle
    time.sleep(2) # Give it a second to start
    print("Running monitor check...")
    monitor.check_processes()

    # 6. Verify it was terminated
    time.sleep(1)
    if not psutil.pid_exists(pid):
        print("SUCCESS: Process was terminated by Hash-Based Blocking!")
    else:
        print("FAILURE: Process is still running.")
        proc.terminate()

if __name__ == "__main__":
    test_hash_blocking()
