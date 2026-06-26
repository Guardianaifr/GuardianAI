#!/usr/bin/env python3
"""
GuardianAI Beta Invite Manager
===============================
Manage closed-beta / testnet user accounts from the command line.
Testers can only access the system if you explicitly create them here.

Usage:
    python beta_invite.py create   --username alice --role analyst
    python beta_invite.py list
    python beta_invite.py revoke   --username alice
    python beta_invite.py reset-pw --username alice
    python beta_invite.py info     --username alice

Roles available:
    read_only     - View events/telemetry only (best for external testers)
    analyst       - View events + run queries (power testers)
    tenant_admin  - Manage their own tenant
    admin         - Full access (internal team only)
"""
from __future__ import annotations

import argparse
import io
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform.startswith("win"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Resolve project root ──────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from backend.auth import AuthManager, hash_password, verify_password  # noqa: E402

# Default DB path — same location the backend uses
DEFAULT_DB = ROOT / "backend" / "guardian.db"

VALID_ROLES = {"read_only", "analyst", "tenant_admin", "admin"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_db_path() -> Path:
    env = os.environ.get("GUARDIAN_DB_PATH", "").strip()
    return Path(env) if env else DEFAULT_DB


def _make_password(length: int = 16) -> str:
    """Generate a human-friendly random password."""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _get_auth() -> AuthManager:
    db = _get_db_path()
    if not db.parent.exists():
        db.parent.mkdir(parents=True, exist_ok=True)
    return AuthManager(db_path=str(db))


def _deactivate_user(db_path: str, username: str) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
    changed = cur.rowcount
    conn.commit()
    conn.close()
    return changed > 0


def _reactivate_user(db_path: str, username: str) -> bool:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_active = 1 WHERE username = ?", (username,))
    changed = cur.rowcount
    conn.commit()
    conn.close()
    return changed > 0


def _set_password(db_path: str, username: str, new_password: str) -> bool:
    pw_hash = hash_password(new_password)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pw_hash, username))
    changed = cur.rowcount
    conn.commit()
    conn.close()
    return changed > 0


def _list_users(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT username, role, tenant_id, is_active, created_at, last_login FROM users ORDER BY created_at"
    )
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({
            "username": r[0],
            "role": r[1],
            "tenant_id": r[2],
            "active": bool(r[3]),
            "created": time.strftime("%Y-%m-%d %H:%M", time.localtime(r[4])) if r[4] else "—",
            "last_login": time.strftime("%Y-%m-%d %H:%M", time.localtime(r[5])) if r[5] else "Never",
        })
    return results


def _print_invite_card(username: str, password: str, role: str, backend_url: str) -> None:
    print()
    print("=" * 62)
    print("  [GUARDIAN] GuardianAI Beta Tester Invite")
    print("=" * 62)
    print(f"  Username   : {username}")
    print(f"  Password   : {password}")
    print(f"  Role       : {role}")
    print(f"  Dashboard  : {backend_url}/site/dashboard.html")
    print(f"  API Login  : POST {backend_url}/api/v1/auth/login")
    print()
    print("  LOGIN COMMAND (curl):")
    print(f'  curl -s -X POST {backend_url}/api/v1/auth/login \\')
    print(f'    -H "Content-Type: application/json" \\')
    print(f'    -d \'{{"username":"{username}","password":"{password}"}}\'')
    print()
    print("  NOTE: Share these credentials privately. Revoke anytime with:")
    print(f"      python beta_invite.py revoke --username {username}")
    print("=" * 62)
    print()


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_create(args: argparse.Namespace) -> int:
    role = args.role
    if role not in VALID_ROLES:
        print(f"[ERROR] Invalid role '{role}'. Choose from: {', '.join(sorted(VALID_ROLES))}")
        return 1

    auth = _get_auth()
    password = args.password if args.password else _make_password()
    tenant = args.tenant or f"beta-{args.username}"

    try:
        user = auth.create_user(
            username=args.username,
            password=password,
            role=role,
            tenant_id=tenant,
        )
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 1

    backend_url = args.backend_url.rstrip("/")
    _print_invite_card(args.username, password, role, backend_url)

    print(f"[OK] User '{args.username}' created (ID={user['id']}, tenant={tenant})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    db = str(_get_db_path())
    users = _list_users(db)

    if not users:
        print("[INFO] No users found in database yet.")
        return 0

    header = f"{'USERNAME':<20} {'ROLE':<14} {'TENANT':<20} {'ACTIVE':<8} {'CREATED':<18} {'LAST LOGIN'}"
    print()
    print(header)
    print("-" * len(header))
    for u in users:
        active_str = "[YES]" if u["active"] else "[NO] "
        print(f"{u['username']:<20} {u['role']:<14} {u['tenant_id']:<20} {active_str:<8} {u['created']:<18} {u['last_login']}")
    print(f"\nTotal: {len(users)} users ({sum(1 for u in users if u['active'])} active)\n")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    db = str(_get_db_path())
    ok = _deactivate_user(db, args.username)
    if ok:
        print(f"[OK] User '{args.username}' revoked. They can no longer log in.")
        return 0
    print(f"[ERROR] User '{args.username}' not found.")
    return 1


def cmd_restore(args: argparse.Namespace) -> int:
    db = str(_get_db_path())
    ok = _reactivate_user(db, args.username)
    if ok:
        print(f"[OK] User '{args.username}' re-activated.")
        return 0
    print(f"[ERROR] User '{args.username}' not found.")
    return 1


def cmd_reset_pw(args: argparse.Namespace) -> int:
    db = str(_get_db_path())
    new_pw = args.password if args.password else _make_password()
    ok = _set_password(db, args.username, new_pw)
    if ok:
        print(f"[OK] Password reset for '{args.username}'.")
        print(f"     New password: {new_pw}")
        return 0
    print(f"[ERROR] User '{args.username}' not found.")
    return 1


def cmd_info(args: argparse.Namespace) -> int:
    auth = _get_auth()
    user = auth.get_user(args.username)
    if not user:
        print(f"[ERROR] User '{args.username}' not found.")
        return 1
    print()
    for k, v in user.items():
        if k in ("created_at", "last_login") and v:
            v = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v))
        print(f"  {k:<14}: {v}")
    print()
    return 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="GuardianAI Beta Invite Manager — closed testnet user management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--backend-url",
        default=os.environ.get("GUARDIAN_BACKEND_URL", "http://localhost:8001"),
        help="Dashboard/API base URL (default: http://localhost:8001)",
    )

    sub = p.add_subparsers(dest="command", required=True)

    # create
    c = sub.add_parser("create", help="Create a new beta tester account")
    c.add_argument("--username", required=True, help="Username for the tester")
    c.add_argument("--role", default="read_only",
                   help="Role: read_only | analyst | tenant_admin | admin (default: read_only)")
    c.add_argument("--password", default="", help="Set custom password (auto-generated if omitted)")
    c.add_argument("--tenant", default="", help="Tenant ID (auto-derived from username if omitted)")

    # list
    sub.add_parser("list", help="List all beta users")

    # revoke
    r = sub.add_parser("revoke", help="Revoke access for a beta tester (soft-delete)")
    r.add_argument("--username", required=True, help="Username to revoke")

    # restore
    rs = sub.add_parser("restore", help="Re-activate a previously revoked account")
    rs.add_argument("--username", required=True, help="Username to restore")

    # reset-pw
    rp = sub.add_parser("reset-pw", help="Reset a user's password")
    rp.add_argument("--username", required=True, help="Username")
    rp.add_argument("--password", default="", help="New password (auto-generated if omitted)")

    # info
    i = sub.add_parser("info", help="Show details for a user")
    i.add_argument("--username", required=True, help="Username")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "create":   cmd_create,
        "list":     cmd_list,
        "revoke":   cmd_revoke,
        "restore":  cmd_restore,
        "reset-pw": cmd_reset_pw,
        "info":     cmd_info,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
