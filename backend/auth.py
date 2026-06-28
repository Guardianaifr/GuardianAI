"""
JWT Authentication Manager for GuardianAI Backend.

Provides token-based authentication with access/refresh token pairs,
argon2id password hashing, and token lifecycle management.

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
import logging

# Argon2id password hashing — industry standard for 2026
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False

_logger = logging.getLogger("guardian_auth")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Secret key for signing tokens — MUST be set in production
_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning(
        "GUARDIAN_JWT_SECRET not set. Using ephemeral key — tokens will be "
        "invalidated on restart. NOT suitable for production."
    )

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = int(os.getenv("GUARDIAN_JWT_ACCESS_TTL", "1800"))       # 30 min default
REFRESH_TOKEN_TTL = int(os.getenv("GUARDIAN_JWT_REFRESH_TTL", "604800"))   # 7 days default


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
# These are the CANONICAL encode/decode functions for the entire project.
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode a string, adding padding as needed."""
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
    """Decode and verify a HS256 JWT token.

    Validates: algorithm (before signature), signature, expiration,
    not-before (nbf), and audience (aud) if present in token.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    header_b64, payload_b64, sig_b64 = parts

    # 1. Decode header FIRST and check algorithm BEFORE signature verification
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as exc:
        raise ValueError("Malformed token header") from exc

    if header.get("alg") != "HS256":
        raise ValueError("Unsupported token algorithm")

    # 2. Verify signature
    signing_input = f"{header_b64}.{payload_b64}"
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    actual_sig = _b64url_decode(sig_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid token signature")

    # 3. Decode payload
    payload = json.loads(_b64url_decode(payload_b64))

    # 4. Check expiration
    if payload.get("exp", 0) < time.time():
        raise ValueError("Token expired")

    # 5. Check not-before (nbf) if present
    nbf = payload.get("nbf")
    if nbf is not None and isinstance(nbf, (int, float)) and time.time() < nbf:
        raise ValueError("Token not yet valid")

    # 6. Check audience (aud) if present — must match JWT_AUDIENCE env if set
    token_aud = payload.get("aud")
    expected_aud = os.getenv("GUARDIAN_JWT_AUDIENCE", "").strip()
    if expected_aud and token_aud:
        # Support single string or list of audiences
        if isinstance(token_aud, str):
            if token_aud != expected_aud:
                raise ValueError("Invalid token audience")
        elif isinstance(token_aud, list):
            if expected_aud not in token_aud:
                raise ValueError("Invalid token audience")

    return payload


# ---------------------------------------------------------------------------
# Password Hashing — Argon2id (industry standard)
# Falls back to legacy SHA-256 verification for pre-existing hashes.
# ---------------------------------------------------------------------------

# Argon2id hasher with recommended parameters
if _ARGON2_AVAILABLE:
    _ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
else:
    _ph = None
    _logger.warning(
        "argon2-cffi not installed. Password hashing will use legacy SHA-256. "
        "Install argon2-cffi for production use."
    )


def hash_password(password: str) -> str:
    """Hash a password using argon2id.

    Falls back to SHA-256+salt if argon2-cffi is not available.
    """
    if _ARGON2_AVAILABLE:
        return _ph.hash(password)
    # Legacy fallback — should not be used in production
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its stored hash.

    Supports both argon2id hashes (prefixed with $argon2) and legacy
    SHA-256+salt hashes (format: salt$hash) for backward compatibility.
    """
    if not hashed:
        return False

    # Argon2 hashes start with $argon2
    if hashed.startswith("$argon2") and _ARGON2_AVAILABLE:
        try:
            return _ph.verify(hashed, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    # Legacy SHA-256+salt fallback (format: hexsalt$hexhash)
    if "$" in hashed and not hashed.startswith("$"):
        salt, expected_hash = hashed.split("$", 1)
        actual_hash = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual_hash, expected_hash)

    return False


def needs_rehash(hashed: str) -> bool:
    """Check if a password hash needs to be re-hashed with argon2id.

    Returns True for:
    - Legacy SHA-256+salt hashes
    - Argon2 hashes with outdated parameters
    - Any non-argon2 hash format
    """
    if not hashed:
        return True
    if not hashed.startswith("$argon2"):
        return True  # Legacy SHA-256 hash
    if _ARGON2_AVAILABLE:
        return _ph.check_needs_rehash(hashed)
    return False


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

        # Rehash with argon2id if the stored hash is legacy SHA-256
        if needs_rehash(pw_hash):
            new_hash = hash_password(password)
            conn = sqlite3.connect(self.db_path)
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
            conn.commit()
            conn.close()

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
