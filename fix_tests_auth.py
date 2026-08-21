import os
import re

files = [
    "tests/backend/test_agentic_control_plane.py",
    "tests/backend/test_backend_audit_summary.py",
    "tests/backend/test_backend_auth_lockout_management.py",
    "tests/backend/test_backend_auth_revocations.py",
    "tests/backend/test_backend_auth_sessions.py",
    "tests/backend/test_backend_auth_whoami.py",
    "tests/backend/test_backend_compliance.py",
    "tests/backend/test_backend_rbac.py",
    "tests/backend/test_backend_rbac_policy.py"
]

for fpath in files:
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # We want to replace "password": "admin-pass" with "password": hash_password("admin-pass")
    # First, make sure hash_password is imported. It might not be.
    # We can just mock it with the legacy SHA256 format for tests to be FAST!
    # A fast dummy hash: "testsalt$..." 
    # Actually, we can just use ackend_main.hash_password("admin-pass") since ackend_main is imported.
    content = re.sub(r'"password": "(admin-pass)"', r'"password": backend_main.hash_password("\1")', content)
    content = re.sub(r'"password": "(auditor-pass)"', r'"password": backend_main.hash_password("\1")', content)
    content = re.sub(r'"password": "(user-pass)"', r'"password": backend_main.hash_password("\1")', content)

    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)

# For tools/test_p2_enterprise.py, it calls _build_auth_users directly, which already uses hash_password, so no change needed there.
