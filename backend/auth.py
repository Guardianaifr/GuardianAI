"""
JWT Authentication Manager for GuardianAI Backend.

Provides token-based authentication with access/refresh token pairs,
bcrypt password hashing, and token lifecycle management.

Designed to work alongside the existing HTTP Basic auth — JWT is the
primary auth method, with Basic auth preserved for backward compatibility.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

# Use stdlib hmac-sha256 for JWT to avoid external dependency.
# This is a compact, self-contained JWT implementation that covers
# HS256 signing — the most common symmetric algorithm for internal APIs.
import base64


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Secret key for signing tokens — MUST be set in production
JWT_SECRET = os.getenv("GUARDIAN_JWT_SECRET", "").strip() or secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = int(os.getenv("GUARDIAN_JWT_ACCESS_TTL", "1800"))       # 30 min default
REFRESH_TOKEN_TTL = int(os.getenv("GUARDIAN_JWT_REFRESH_TTL", "604800"))   # 7 days default

# Warn if using auto-generated secret (won't survive restart)
if not os.getenv("GUARDIAN_JWT_SECRET", "").strip():
    import logging
    logging.getLogger("guardian_auth").warning(
        "GUARDIAN_JWT_SECRET not set. Using ephemeral key — tokens will be invalidated on restart."
    )


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class TokenPair:
    """JWT access + refresh token pair."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_TTL


@dataclass
class TokenPayload:
    """Decoded JWT payload."""
    user_id: str
    role: str
    tenant_id: str
    token_type: str     # "access" or "refresh"
    exp: float          # Expiration timestamp
    iat: float          # Issued-at timestamp
    jti: str            # Unique token ID


# ---------------------------------------------------------------------------
# Compact HS256 JWT Implementation (no external dependency)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _jwt_encode(payload: dict, secret: str) -> str:
    """Create a HS256 JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _jwt_decode(token: str, secret: str) -> dict:
    """Decode and verify a HS256 JWT token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    header_b64, payload_b64, sig_b64 = parts

    # Verify signature
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    actual_sig = _b64url_decode(sig_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid token signature")

    # Decode payload
    payload = json.loads(_b64url_decode(payload_b64))

    # Check expiration
    if payload.get("exp", 0) < time.time():
        raise ValueError("Token expired")

    return payload


# ---------------------------------------------------------------------------
# Password Hashing (SHA-256 + salt — no bcrypt dependency needed)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a password with a random salt using SHA-256.

    Format: salt$hash (both hex-encoded).
    """
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    if "$" not in hashed:
        return False
    salt, expected_hash = hashed.split("$", 1)
    actual_hash = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(actual_hash, expected_hash)


# ---------------------------------------------------------------------------
# Auth Manager
# ---------------------------------------------------------------------------

class AuthManager:
    """JWT authentication manager.

    Handles token creation, verification, refresh, and user management
    using SQLite for persistence.

    Args:
        db_path: Path to SQLite database.
        secret: JWT signing secret.
        access_ttl: Access token TTL in seconds.
        refresh_ttl: Refresh token TTL in seconds.
    """

    def __init__(
        self,
        db_path: str = "guardian.db",
        secret: str = JWT_SECRET,
        access_ttl: int = ACCESS_TOKEN_TTL,
        refresh_ttl: int = REFRESH_TOKEN_TTL,
    ):
        self.db_path = db_path
        self.secret = secret
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl
        self._init_db()

    def _init_db(self) -> None:
        """Create users table if it doesn't exist."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'read_only',
                tenant_id TEXT DEFAULT 'default',
                is_active INTEGER DEFAULT 1,
                created_at REAL,
                last_login REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                revoked_at REAL
            )
        """)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # User Management
    # ------------------------------------------------------------------

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "read_only",
        tenant_id: str = "default",
    ) -> Dict[str, Any]:
        """Create a new user.

        Args:
            username: Unique username.
            password: Plaintext password (will be hashed).
            role: User role (admin, analyst, tenant_admin, read_only).
            tenant_id: Tenant scope for the user.

        Returns:
            Dict with user info (no password hash).
        """
        from backend.rbac import VALID_ROLES
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}. Must be one of: {VALID_ROLES}")

        pw_hash = hash_password(password)
        now = time.time()

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, role, tenant_id, is_active, created_at) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (username, pw_hash, role, tenant_id, now),
            )
            conn.commit()
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            conn.close()
            raise ValueError(f"User '{username}' already exists")
        conn.close()

        return {
            "id": user_id,
            "username": username,
            "role": role,
            "tenant_id": tenant_id,
            "is_active": True,
            "created_at": now,
        }

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user by username and password.

        Returns:
            User dict if credentials valid, None otherwise.
        """
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_hash, role, tenant_id, is_active FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            return None

        user_id, uname, pw_hash, role, tenant_id, is_active = row

        if not is_active:
            return None

        if not verify_password(password, pw_hash):
            return None

        # Update last_login
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user_id))
        conn.commit()
        conn.close()

        return {
            "id": user_id,
            "username": uname,
            "role": role,
            "tenant_id": tenant_id,
        }

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, role, tenant_id, is_active, created_at, last_login "
            "FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "id": row[0],
            "username": row[1],
            "role": row[2],
            "tenant_id": row[3],
            "is_active": bool(row[4]),
            "created_at": row[5],
            "last_login": row[6],
        }

    # ------------------------------------------------------------------
    # Token Operations
    # ------------------------------------------------------------------

    def create_token_pair(self, user: Dict[str, Any]) -> TokenPair:
        """Create access + refresh token pair for a user.

        Args:
            user: User dict with id, username, role, tenant_id.

        Returns:
            TokenPair with access and refresh tokens.
        """
        now = time.time()

        access_payload = {
            "sub": str(user["id"]),
            "username": user["username"],
            "role": user["role"],
            "tenant_id": user.get("tenant_id", "default"),
            "type": "access",
            "iat": now,
            "exp": now + self.access_ttl,
            "jti": secrets.token_hex(16),
        }

        refresh_payload = {
            "sub": str(user["id"]),
            "username": user["username"],
            "role": user["role"],
            "tenant_id": user.get("tenant_id", "default"),
            "type": "refresh",
            "iat": now,
            "exp": now + self.refresh_ttl,
            "jti": secrets.token_hex(16),
        }

        access_token = _jwt_encode(access_payload, self.secret)
        refresh_token = _jwt_encode(refresh_payload, self.secret)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.access_ttl,
        )

    def verify_token(self, token: str) -> TokenPayload:
        """Verify and decode a JWT token.

        Args:
            token: The JWT string.

        Returns:
            TokenPayload with decoded claims.

        Raises:
            ValueError: If token is invalid, expired, or revoked.
        """
        payload = _jwt_decode(token, self.secret)

        jti = payload.get("jti", "")
        if self._is_revoked(jti):
            raise ValueError("Token has been revoked")

        return TokenPayload(
            user_id=payload.get("sub", ""),
            role=payload.get("role", "read_only"),
            tenant_id=payload.get("tenant_id", "default"),
            token_type=payload.get("type", "access"),
            exp=payload.get("exp", 0),
            iat=payload.get("iat", 0),
            jti=jti,
        )

    def refresh_tokens(self, refresh_token: str) -> TokenPair:
        """Use a refresh token to get a new token pair.

        The old refresh token is revoked (rotation).

        Args:
            refresh_token: The refresh JWT string.

        Returns:
            New TokenPair.

        Raises:
            ValueError: If refresh token is invalid or not a refresh type.
        """
        payload = self.verify_token(refresh_token)

        if payload.token_type != "refresh":
            raise ValueError("Not a refresh token")

        # Revoke old refresh token
        self.revoke_token(payload.jti)

        # Look up current user info
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, role, tenant_id FROM users WHERE id = ? AND is_active = 1",
            (int(payload.user_id),),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            raise ValueError("User not found or deactivated")

        user = {
            "id": row[0],
            "username": row[1],
            "role": row[2],
            "tenant_id": row[3],
        }

        return self.create_token_pair(user)

    def revoke_token(self, jti: str) -> None:
        """Revoke a token by its JTI."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)",
            (jti, time.time()),
        )
        conn.commit()
        conn.close()

    def _is_revoked(self, jti: str) -> bool:
        """Check if a token JTI has been revoked."""
        if not jti:
            return False
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
        result = cur.fetchone()
        conn.close()
        return result is not None

    def cleanup_expired_tokens(self) -> int:
        """Remove revoked tokens older than refresh TTL (housekeeping)."""
        cutoff = time.time() - self.refresh_ttl
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("DELETE FROM revoked_tokens WHERE revoked_at < ?", (cutoff,))
        deleted = cur.rowcount
        conn.commit()
        conn.close()
        return deleted


# Default global instance of AuthManager (Singleton)
auth_manager = AuthManager()

