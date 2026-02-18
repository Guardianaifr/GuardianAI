# Backend Hardening Demo Guide (New Controls)

This guide covers the backend hardening controls we implemented recently.

It does **not** use the existing `demo_1_safe.bat` through `demo_6_rate_limit.bat` scenarios.

## Prerequisite

1. Run `demo_hardening_0_start_backend.bat` in one terminal and keep it open.
2. Run the remaining demo scripts in any order, but the sequence below is recommended.

## Recommended Sequence

1. `demo_hardening_1_posture.bat`  
Why: establishes current security posture before deeper tests.  
What it does: checks `/health`, `/metrics`, compliance report, and RBAC policy.

2. `demo_hardening_2_identity_rbac.bat`  
Why: validates least-privilege role separation.  
What it does: issues tokens for all roles and shows `whoami` permissions.

3. `demo_hardening_3_session_inventory.bat`  
Why: proves visibility and access boundaries for active sessions.  
What it does: auditor can list sessions; user role is blocked.

4. `demo_hardening_4_revoke_self.bat`  
Why: enables user-led containment without admin dependency.  
What it does: revokes other user sessions while keeping current session active.

5. `demo_hardening_5_revoke_self_jti.bat`  
Why: enables precise session kill for one compromised token/device.  
What it does: revokes one owned JTI; blocks current-session and foreign-session attempts.

6. `demo_hardening_6_lockout_management.bat`  
Why: demonstrates brute-force protection and operational recovery.  
What it does: triggers lockout, verifies `429`, audits lockout list, clears lockout.

7. `demo_hardening_7_admin_containment.bat`  
Why: demonstrates rapid incident containment for admin operations.  
What it does: uses `revoke-user` and `revoke-all` (self-exclusion) controls.

8. `demo_hardening_8_api_key_lifecycle.bat`  
Why: validates key hygiene for telemetry ingestion controls.  
What it does: create, list, rotate, and revoke managed API keys.

9. `demo_hardening_9_audit_integrity.bat`  
Why: proves tamper evidence and delivery retry operations.  
What it does: chain verify, summary review, failure queue list, retry execution.

## Notes

- All scripts print expected behavior and fail fast with non-zero exit on errors.
- You can pass optional args through each `.bat`, for example:
  - `demo_hardening_1_posture.bat --base-url http://127.0.0.1:8001`
  - `demo_hardening_2_identity_rbac.bat --admin-pass admin-pass`
