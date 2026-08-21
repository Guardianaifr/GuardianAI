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
    import sys
    if os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        _logger.error("CRITICAL SECURITY ERROR: GUARDIAN_JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
        
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning("GUARDIAN_JWT_SECRET not set. Using ephemeral key. NOT suitable for production.")

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

    # 6. Check audience (aud) — must match JWT_AUDIENCE env if set
    token_aud = payload.get("aud")
    expected_aud = os.getenv("GUARDIAN_JWT_AUDIENCE", "").strip()
    if expected_aud:
        if not token_aud:
            raise ValueError("Missing token audience")
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
    _ph = PasswordHasher(time_cost=7, memory_cost=65536, parallelism=4)
else:
    _ph = None
    if os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        raise RuntimeError(
            "CRITICAL SECURITY ERROR: argon2-cffi is not installed or failed to load, "
            "but system is running in PRODUCTION mode. Refusing to fall back to legacy SHA-256 password hashing."
        )
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
    if os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        raise RuntimeError("Argon2 is unavailable in production mode.")
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
