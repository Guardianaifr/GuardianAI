import os
import subprocess
import sys

# Inherit all environment variables currently set in the executing CMD shell
env = os.environ.copy()

# Force inject the exact environment variables required by the Demo Backend Hardening suite
env["GUARDIAN_ADMIN_USER"] = "admin"
env["GUARDIAN_ADMIN_PASS"] = "guardian26"
env["GUARDIAN_AUDITOR_USER"] = "auditor"
env["GUARDIAN_AUDITOR_PASS"] = "auditor-pass"
env["GUARDIAN_USER_USER"] = "user1"
env["GUARDIAN_USER_PASS"] = "user-pass"
env["GUARDIAN_JWT_SECRET"] = "demo-super-secret-change-me"
env["GUARDIAN_AUTH_LOCKOUT_ENABLED"] = "true"
env["GUARDIAN_AUTH_LOCKOUT_MAX_ATTEMPTS"] = "5"
env["GUARDIAN_AUTH_LOCKOUT_DURATION_SEC"] = "60"

# Launch guardianctl start in a detached creation state so the shell can continue
cmd = [sys.executable, "guardianctl.py", "start"]
CREATE_NO_WINDOW = 0x08000000

log_file = open("guardian_background.log", "a")
subprocess.Popen(
    cmd,
    env=env,
    creationflags=CREATE_NO_WINDOW,
    stdout=log_file,
    stderr=log_file,
    stdin=subprocess.DEVNULL
)
