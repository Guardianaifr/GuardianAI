import pytest
import os
import sys
import sqlite3
from typing import Dict, Any
from unittest.mock import patch, MagicMock

from fastapi import HTTPException
from backend.security.url_validation import is_safe_url
from backend.security.authorization import can_access_tenant, can_access_agent
from guardian.passport.passport_core import PassportEngine, AgentPassport


def test_url_validation_basic():
    # Loopback IP
    assert is_safe_url("http://127.0.0.1/api") is False
    assert is_safe_url("http://localhost/api") is False

    # Private ranges
    assert is_safe_url("http://192.168.1.1/api") is False
    assert is_safe_url("http://10.0.0.1/api") is False
    assert is_safe_url("http://172.16.0.1/api") is False

    # External safe domain (should resolve successfully)
    # Note: depends on network resolution, but we check logic.
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]
        assert is_safe_url("https://dns.google/resolve") is True


def test_url_validation_env_overrides():
    # Local host check with env var override
    with patch.dict(os.environ, {"GUARDIAN_ALLOW_INTERNAL_TEST_HOSTS": "true", "GUARDIAN_ENV": "development"}):
        assert is_safe_url("http://localhost/api") is True
        assert is_safe_url("http://192.168.1.1/api") is True

    # In production, HTTP scheme is always blocked even if test hosts are allowed
    with patch.dict(os.environ, {"GUARDIAN_ALLOW_INTERNAL_TEST_HOSTS": "true", "GUARDIAN_ENV": "production"}):
        assert is_safe_url("http://localhost/api") is False
        assert is_safe_url("https://localhost/api") is True


def test_authorization_helpers():
    # Caller profiles
    admin_principal = {"username": "admin", "role": "admin", "org_id": "org_guardian"}
    global_auditor_principal = {"username": "global_aud", "role": "auditor", "org_id": "org_guardian"}
    tenant_auditor_principal = {"username": "tenant_aud", "role": "auditor", "org_id": "tenant_a"}
    user_principal = {"username": "user1", "role": "user", "org_id": "tenant_a"}

    # Admins have access to everything
    assert can_access_tenant(admin_principal, "tenant_a") is True
    assert can_access_tenant(admin_principal, "tenant_b") is True

    # Global auditors (auditor role in org_guardian) have access to everything
    assert can_access_tenant(global_auditor_principal, "tenant_a") is True
    assert can_access_tenant(global_auditor_principal, "tenant_b") is True

    # Tenant-scoped auditors are restricted to their own tenant
    assert can_access_tenant(tenant_auditor_principal, "tenant_a") is True
    assert can_access_tenant(tenant_auditor_principal, "tenant_b") is False

    # Regular users are restricted to their own tenant
    assert can_access_tenant(user_principal, "tenant_a") is True
    assert can_access_tenant(user_principal, "tenant_b") is False


def test_passport_engine_tenant_id(tmp_path):
    db_file = str(tmp_path / "test_rem.db")
    
    # 1. Initialize DB and verify column exists
    engine = PassportEngine(db_path=db_file)
    passport = engine.issue_passport("agent-x", "0xpubkey", tenant_id="tenant_a")
    assert passport.tenant_id == "tenant_a"

    # 2. Retrieve and assert tenant_id matches
    retrieved = engine.get_passport("agent-x")
    assert retrieved is not None
    assert retrieved.tenant_id == "tenant_a"


def test_passport_migration_trail(tmp_path):
    db_file = str(tmp_path / "test_migration.db")
    
    # Initialize a legacy DB without tenant_id column
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE agent_passports (
            passport_id   TEXT PRIMARY KEY,
            agent_id      TEXT UNIQUE NOT NULL,
            owner_pubkey  TEXT NOT NULL,
            chain_id      TEXT DEFAULT 'base',
            trust_score   REAL DEFAULT 0.0,
            tier          TEXT DEFAULT 'UNVERIFIED',
            credentials   TEXT DEFAULT '[]',
            metadata      TEXT DEFAULT '{}',
            issued_at     REAL,
            updated_at    REAL,
            is_active     INTEGER DEFAULT 1,
            cortex_events_count INTEGER DEFAULT 0,
            last_anchor_tx TEXT DEFAULT ''
        )
    """)
    cur.execute("""
        INSERT INTO agent_passports (passport_id, agent_id, owner_pubkey)
        VALUES ('pid-1', 'agent-legacy', '0xlegacy')
    """)
    conn.commit()
    conn.close()

    # Instantiate PassportEngine, which should run migration and log to stdout
    with patch("builtins.print") as mock_print:
        engine = PassportEngine(db_path=db_file)
        # Verify print was called containing our audit log message
        mock_print.assert_any_call("[PASSPORT MIGRATION AUDIT] Migrated passport agent-legacy to default tenant")

    # Verify the retrieved legacy passport has tenant_id = 'default'
    legacy_passport = engine.get_passport("agent-legacy")
    assert legacy_passport is not None
    assert legacy_passport.tenant_id == "default"
