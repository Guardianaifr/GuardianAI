# Real-Time OpenClaw Demo Guide

This guide demonstrates GuardianAI against your live OpenClaw endpoint.

## 1. Start Live Stack

Run:

`demo_realtime_openclaw_0_start_stack.bat`

It will prompt for:
- OpenClaw base URL (example: `http://127.0.0.1:8080`)
- optional bearer key (if your OpenClaw requires upstream auth)

The script then starts:
- backend: `http://127.0.0.1:8001`
- proxy: `http://127.0.0.1:8081`

Keep this terminal open.

## 2. Run Real-Time Demos

Run each in a separate terminal:

1. `demo_realtime_openclaw_1_safe_allow.bat`  
Validates benign prompt pass-through and `allowed_request` telemetry.

2. `demo_realtime_openclaw_2_injection_block.bat`  
Validates prompt injection blocking (`403`) and blocked-event telemetry.

3. `demo_realtime_openclaw_3_pii_protection.bat`  
Validates data leak / redaction handling and related telemetry events.

## 3. Optional: Run Backend Hardening Demos Too

After the live stack is running, you can also run:
- `demo_hardening_1_posture.bat` ... `demo_hardening_9_audit_integrity.bat`

Those cover auth sessions, lockout, API key lifecycle, and audit operations.
