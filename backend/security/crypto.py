import base64
import hashlib
import hmac
import logging
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("guardian_backend.crypto")


def _get_agentic_secret(override: Optional[str] = None) -> str:
    if override:
        return override
    try:
        import sys
        if "backend.main" in sys.modules:
            val = getattr(sys.modules["backend.main"], "AGENTIC_ATTESTATION_SECRET", None)
            if val:
                return val
    except (ImportError, AttributeError):
        pass
    try:
        from backend import config
        return getattr(config, "AGENTIC_ATTESTATION_SECRET", "")
    except (ImportError, AttributeError):
        return os.getenv("GUARDIAN_AGENTIC_ATTESTATION_SECRET", "")


def _get_env_mode(override: Optional[str] = None) -> str:
    if override:
        return override
    try:
        import sys
        if "backend.main" in sys.modules:
            val = getattr(sys.modules["backend.main"], "_env_mode", None)
            if val:
                return val
    except (ImportError, AttributeError):
        pass
    try:
        from backend import config
        return getattr(config, "_env_mode", "development")
    except (ImportError, AttributeError):
        return os.getenv("GUARDIAN_ENV", "development").strip().lower()


def _get_aead_key(secret: Optional[str] = None) -> bytes:
    sec = _get_agentic_secret(secret)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"guardian_agentic_v2",
        info=b"agentic_attestation_key",
    )
    return hkdf.derive(sec.encode("utf-8"))


def _agentic_encrypt_secret(raw_secret: str, secret: Optional[str] = None) -> str:
    key = _get_aead_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    raw = raw_secret.encode("utf-8")
    ct = aesgcm.encrypt(nonce, raw, None)
    return "v2:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def _agentic_decrypt_secret(
    ciphertext: str,
    secret: Optional[str] = None,
    env_mode: Optional[str] = None,
) -> str:
    if ciphertext.startswith("v2:"):
        data = base64.urlsafe_b64decode(ciphertext[3:].encode("ascii"))
        nonce = data[:12]
        ct = data[12:]
        key = _get_aead_key(secret)
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
        except (ValueError, TypeError, Exception) as e:
            if type(e).__name__ == "InvalidTag" or isinstance(e, ValueError):
                raise ValueError("Decryption failed")
            raise e
    else:
        raise ValueError("Unsupported or legacy secret format: AES-GCM (v2) required")


def _hash_agentic_secret(raw_secret: str, secret: Optional[str] = None) -> str:
    sec = _get_agentic_secret(secret)
    return hmac.new(
        sec.encode("utf-8"),
        raw_secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _new_agentic_secret() -> str:
    return "ga_" + secrets.token_urlsafe(32)


__all__ = [
    "_get_aead_key",
    "_agentic_encrypt_secret",
    "_agentic_decrypt_secret",
    "_hash_agentic_secret",
    "_new_agentic_secret",
]
