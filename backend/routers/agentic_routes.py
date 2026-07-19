from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import time
import json
import sqlite3
import secrets

from backend.main import (
    AgenticConfigSnapshotResponse,
    AgenticExecutionGrantRequest,
    AgenticExecutionGrantResponse,
    AgenticKeyCreateRequest,
    AgenticKeyResponse,
    AgenticMetricsResponse,
    AgenticPolicyEdgeRequest,
    AgenticPolicyEdgeResponse,
    AgenticRevokeRequest,
    CreatedAgenticKeyResponse,
    DB_PATH,
    _agentic_edge_response,
    _agentic_encrypt_secret,
    _agentic_grant_response,
    _agentic_key_response,
    _build_agentic_config_snapshot,
    _build_agentic_metrics,
    _hash_agentic_secret,
    _new_agentic_secret,
    _normalize_agentic_id,
    _normalize_cert_fingerprint,
    _write_control_plane_audit_entry,
    enforce_admin_rate_limit,
    enforce_auditor_rate_limit,
)

router = APIRouter()

@router.post("/api/v1/agentic/keys", response_model=CreatedAgenticKeyResponse)
async def create_agentic_key(payload: AgenticKeyCreateRequest, username: str = Depends(enforce_admin_rate_limit)):
    agent_id = _normalize_agentic_id(payload.agent_id, "agent_id")
    key_id = _normalize_agentic_id(payload.key_id or f"key-{secrets.token_hex(6)}", "key_id")
    cert_fingerprints = [
        fp for fp in (_normalize_cert_fingerprint(v) for v in payload.cert_fingerprints) if fp
    ]
    cert_fingerprints_json = json.dumps(cert_fingerprints, separators=(",", ":"))
    raw_secret = _new_agentic_secret()
    secret_hash = _hash_agentic_secret(raw_secret)
    ciphertext = _agentic_encrypt_secret(raw_secret)
    created_at = time.time()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO agentic_agent_keys
                (agent_id, key_id, key_secret_hash, key_secret_ciphertext, cert_fingerprints_json, status, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (agent_id, key_id, secret_hash, ciphertext, cert_fingerprints_json, username, created_at),
        )
        key_db_id = cur.lastrowid
        conn.commit()
        cur.execute(
            """
            SELECT id, agent_id, key_id, key_secret_hash, key_secret_ciphertext, cert_fingerprints_json, status, created_by,
                   created_at, rotated_at, revoked_at, revoked_by, revoke_reason
            FROM agentic_agent_keys WHERE id = ?
            """,
            (key_db_id,),
        )
        row = cur.fetchone()
    except sqlite3.IntegrityError as exc:
        conn.close()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="agent key already exists") from exc
    conn.close()

    _write_control_plane_audit_entry(
        "agentic_key_created",
        username,
        {
            "agent_id": agent_id,
            "key_id": key_id,
            "key_secret_hash": secret_hash,
            "cert_fingerprints": cert_fingerprints,
        },
    )
    return _agentic_key_response(row, include_secret=raw_secret)


@router.get("/api/v1/agentic/keys", response_model=List[AgenticKeyResponse])
async def list_agentic_keys(username: str = Depends(enforce_auditor_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, agent_id, key_id, key_secret_hash, key_secret_ciphertext, cert_fingerprints_json, status, created_by,
               created_at, rotated_at, revoked_at, revoked_by, revoke_reason
        FROM agentic_agent_keys
        ORDER BY created_at DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [_agentic_key_response(row) for row in rows]


@router.post("/api/v1/agentic/keys/{key_db_id}/rotate", response_model=CreatedAgenticKeyResponse)
async def rotate_agentic_key(key_db_id: int, username: str = Depends(enforce_admin_rate_limit)):
    raw_secret = _new_agentic_secret()
    secret_hash = _hash_agentic_secret(raw_secret)
    ciphertext = _agentic_encrypt_secret(raw_secret)
    rotated_at = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE agentic_agent_keys
        SET key_secret_hash = ?, key_secret_ciphertext = ?, status = 'active',
            rotated_at = ?, revoked_at = NULL, revoked_by = NULL, revoke_reason = NULL
        WHERE id = ?
        """,
        (secret_hash, ciphertext, rotated_at, key_db_id),
    )
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent key not found")
    conn.commit()
    cur.execute(
        """
        SELECT id, agent_id, key_id, key_secret_hash, key_secret_ciphertext, cert_fingerprints_json, status, created_by,
               created_at, rotated_at, revoked_at, revoked_by, revoke_reason
        FROM agentic_agent_keys WHERE id = ?
        """,
        (key_db_id,),
    )
    row = cur.fetchone()
    conn.close()
    _write_control_plane_audit_entry(
        "agentic_key_rotated",
        username,
        {"agent_id": row[1], "key_id": row[2], "key_secret_hash": secret_hash},
    )
    return _agentic_key_response(row, include_secret=raw_secret)


@router.post("/api/v1/agentic/revocations")
async def revoke_agentic_identity(payload: AgenticRevokeRequest, username: str = Depends(enforce_admin_rate_limit)):
    agent_id = _normalize_agentic_id(payload.agent_id, "agent_id")
    key_id = _normalize_agentic_id(payload.key_id, "key_id") if payload.key_id else None
    revocation_type = "key" if key_id else "agent"
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO agentic_revocations (revocation_type, agent_id, key_id, reason, revoked_by, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (revocation_type, agent_id, key_id, payload.reason, username, now),
    )
    if key_id:
        cur.execute(
            """
            UPDATE agentic_agent_keys
            SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoke_reason = ?
            WHERE agent_id = ? AND key_id = ?
            """,
            (now, username, payload.reason, agent_id, key_id),
        )
    else:
        cur.execute(
            """
            UPDATE agentic_agent_keys
            SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoke_reason = ?
            WHERE agent_id = ?
            """,
            (now, username, payload.reason, agent_id),
        )
    affected_keys = cur.rowcount
    conn.commit()
    conn.close()
    _write_control_plane_audit_entry(
        "agentic_identity_revoked",
        username,
        {"revocation_type": revocation_type, "agent_id": agent_id, "key_id": key_id, "affected_keys": affected_keys},
    )
    return {
        "revocation_type": revocation_type,
        "agent_id": agent_id,
        "key_id": key_id,
        "affected_keys": affected_keys,
        "revoked_at": now,
    }


@router.post("/api/v1/agentic/grants", response_model=AgenticExecutionGrantResponse)
async def create_agentic_grant(payload: AgenticExecutionGrantRequest, username: str = Depends(enforce_admin_rate_limit)):
    execution_id = _normalize_agentic_id(payload.execution_id, "execution_id")
    agent_id = _normalize_agentic_id(payload.agent_id, "agent_id") if payload.agent_id else None
    parent_agent = _normalize_agentic_id(payload.parent_agent, "parent_agent") if payload.parent_agent else None
    ttl_seconds = min(max(int(payload.ttl_seconds), 1), 86400)
    created_at = time.time()
    expires_at = created_at + ttl_seconds
    scopes_json = json.dumps([str(v) for v in payload.scopes], separators=(",", ":"))
    tools_json = json.dumps([str(v) for v in payload.tools], separators=(",", ":"))
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO agentic_execution_grants
                (execution_id, agent_id, parent_agent, scopes_json, tools_json, expires_at, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (execution_id, agent_id, parent_agent, scopes_json, tools_json, expires_at, username, created_at),
        )
        grant_id = cur.lastrowid
        conn.commit()
        cur.execute(
            """
            SELECT id, execution_id, agent_id, parent_agent, scopes_json, tools_json, expires_at,
                   created_by, created_at, revoked_at, revoked_by, revoke_reason
            FROM agentic_execution_grants WHERE id = ?
            """,
            (grant_id,),
        )
        row = cur.fetchone()
    except sqlite3.IntegrityError as exc:
        conn.close()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="execution grant already exists") from exc
    conn.close()
    _write_control_plane_audit_entry(
        "agentic_execution_grant_created",
        username,
        {"execution_id": execution_id, "agent_id": agent_id, "parent_agent": parent_agent, "expires_at": expires_at},
    )
    return _agentic_grant_response(row)


@router.get("/api/v1/agentic/grants", response_model=List[AgenticExecutionGrantResponse])
async def list_agentic_grants(active_only: bool = False, username: str = Depends(enforce_auditor_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    base_sql = """
        SELECT id, execution_id, agent_id, parent_agent, scopes_json, tools_json, expires_at,
               created_by, created_at, revoked_at, revoked_by, revoke_reason
        FROM agentic_execution_grants
    """
    if active_only:
        cur.execute(base_sql + " WHERE revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC", (time.time(),))
    else:
        cur.execute(base_sql + " ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [_agentic_grant_response(row) for row in rows]


@router.post("/api/v1/agentic/grants/{execution_id}/revoke")
async def revoke_agentic_grant(
    execution_id: str,
    reason: str | None = None,
    username: str = Depends(enforce_admin_rate_limit),
):
    normalized_exec_id = _normalize_agentic_id(execution_id, "execution_id")
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE agentic_execution_grants
        SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
        WHERE execution_id = ?
        """,
        (now, username, reason, normalized_exec_id),
    )
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="execution grant not found")
    conn.commit()
    conn.close()
    _write_control_plane_audit_entry(
        "agentic_execution_grant_revoked",
        username,
        {"execution_id": normalized_exec_id, "reason": reason},
    )
    return {"execution_id": normalized_exec_id, "revoked_at": now, "reason": reason}


@router.post("/api/v1/agentic/policy-edges", response_model=AgenticPolicyEdgeResponse)
async def upsert_agentic_policy_edge(
    payload: AgenticPolicyEdgeRequest,
    username: str = Depends(enforce_admin_rate_limit),
):
    parent_agent = _normalize_agentic_id(payload.parent_agent, "parent_agent")
    child_agent = _normalize_agentic_id(payload.child_agent, "child_agent")
    scopes_json = json.dumps([str(v) for v in payload.scopes], separators=(",", ":"))
    tools_json = json.dumps([str(v) for v in payload.tools], separators=(",", ":"))
    created_at = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO agentic_policy_edges
            (parent_agent, child_agent, scopes_json, tools_json, max_hops, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(parent_agent, child_agent) DO UPDATE SET
            scopes_json = excluded.scopes_json,
            tools_json = excluded.tools_json,
            max_hops = excluded.max_hops,
            created_by = excluded.created_by,
            created_at = excluded.created_at
        """,
        (parent_agent, child_agent, scopes_json, tools_json, payload.max_hops, username, created_at),
    )
    conn.commit()
    cur.execute(
        """
        SELECT id, parent_agent, child_agent, scopes_json, tools_json, max_hops, created_by, created_at
        FROM agentic_policy_edges
        WHERE parent_agent = ? AND child_agent = ?
        """,
        (parent_agent, child_agent),
    )
    row = cur.fetchone()
    conn.close()
    _write_control_plane_audit_entry(
        "agentic_policy_edge_upserted",
        username,
        {"parent_agent": parent_agent, "child_agent": child_agent},
    )
    return _agentic_edge_response(row)


@router.get("/api/v1/agentic/policy-edges", response_model=List[AgenticPolicyEdgeResponse])
async def list_agentic_policy_edges(username: str = Depends(enforce_auditor_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, parent_agent, child_agent, scopes_json, tools_json, max_hops, created_by, created_at
        FROM agentic_policy_edges
        ORDER BY parent_agent, child_agent
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [_agentic_edge_response(row) for row in rows]


@router.get("/api/v1/agentic/config-snapshot", response_model=AgenticConfigSnapshotResponse)
async def get_agentic_config_snapshot(username: str = Depends(enforce_admin_rate_limit)):
    return _build_agentic_config_snapshot()


@router.get("/api/v1/agentic/metrics", response_model=AgenticMetricsResponse)
async def get_agentic_metrics(username: str = Depends(enforce_auditor_rate_limit)):
    return _build_agentic_metrics()
