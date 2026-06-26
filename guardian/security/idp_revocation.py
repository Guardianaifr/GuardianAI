"""External IdP/JWT revocation client."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class RevocationSubject:
    session_id: str
    token_hash: str | None = None
    jwt_sub: str | None = None
    jwt_jti: str | None = None
    raw_jwt: str | None = None


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode((payload + padding).encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def build_subject(session_id: str, raw_jwt: str | None, include_raw_jwt: bool = False) -> RevocationSubject:
    token_hash = None
    jwt_sub = None
    jwt_jti = None
    raw = None
    if raw_jwt:
        token_hash = hashlib.sha256(raw_jwt.encode("utf-8")).hexdigest()
        claims = _decode_jwt_claims(raw_jwt)
        jwt_sub = str(claims.get("sub")) if claims.get("sub") is not None else None
        jwt_jti = str(claims.get("jti")) if claims.get("jti") is not None else None
        if include_raw_jwt:
            raw = raw_jwt
    return RevocationSubject(
        session_id=session_id,
        token_hash=token_hash,
        jwt_sub=jwt_sub,
        jwt_jti=jwt_jti,
        raw_jwt=raw,
    )


class IdpRevocationClient:
    def __init__(self, cfg: dict[str, Any] | None = None):
        cfg = cfg or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.url = str(cfg.get("url", "")).strip()
        self.provider_auth = str(cfg.get("token", "")).strip()
        self.provider = str(cfg.get("provider", "generic")).strip().lower() or "generic"
        self.timeout_seconds = float(cfg.get("timeout_seconds", 2))
        self.max_retries = int(cfg.get("max_retries", 1))
        self.include_raw_jwt = bool(cfg.get("include_raw_jwt", False))
        self.cfg = cfg

    def _build_generic_request(self, subject: RevocationSubject, reason: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        payload = {
            "session_id": subject.session_id,
            "reason": reason,
            "timestamp": time.time(),
            "token_hash": subject.token_hash,
            "jwt_sub": subject.jwt_sub,
            "jwt_jti": subject.jwt_jti,
        }
        if self.include_raw_jwt and subject.raw_jwt:
            payload["raw_jwt"] = subject.raw_jwt
        headers = {"Content-Type": "application/json"}
        if self.provider_auth:
            headers["Authorization"] = f"Bearer {self.provider_auth}"
        return self.url, payload, headers

    def _build_okta_request(self, subject: RevocationSubject, reason: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        url = str(self.cfg.get("okta_revoke_url") or self.url).strip()
        payload = {
            "event_type": "guardian.session.revoke",
            "reason": reason,
            "timestamp": time.time(),
            "subject": {
                "session_id": subject.session_id,
                "sub": subject.jwt_sub,
                "jti": subject.jwt_jti,
                "token_hash": subject.token_hash,
            },
        }
        headers = {"Content-Type": "application/json"}
        if self.provider_auth:
            headers["Authorization"] = f"SSWS {self.provider_auth}"
        return url, payload, headers

    def _build_auth0_request(self, subject: RevocationSubject, reason: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        url = str(self.cfg.get("auth0_revoke_url") or self.url).strip()
        payload = {
            "reason": reason,
            "timestamp": time.time(),
            "sub": subject.jwt_sub,
            "jti": subject.jwt_jti,
            "session_id": subject.session_id,
            "token_hash": subject.token_hash,
        }
        headers = {"Content-Type": "application/json"}
        if self.provider_auth:
            headers["Authorization"] = f"Bearer {self.provider_auth}"
        return url, payload, headers

    def _build_azure_request(self, subject: RevocationSubject, reason: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        url = str(self.cfg.get("azure_revoke_url") or self.url).strip()
        payload = {
            "sessionId": subject.session_id,
            "userId": subject.jwt_sub,
            "tokenId": subject.jwt_jti,
            "tokenHash": subject.token_hash,
            "reason": reason,
            "timestamp": time.time(),
        }
        headers = {"Content-Type": "application/json"}
        if self.provider_auth:
            headers["Authorization"] = f"Bearer {self.provider_auth}"
        return url, payload, headers

    def _build_provider_request(self, subject: RevocationSubject, reason: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        if self.provider == "okta":
            return self._build_okta_request(subject, reason)
        if self.provider == "auth0":
            return self._build_auth0_request(subject, reason)
        if self.provider in {"azure", "azuread", "azure_ad"}:
            return self._build_azure_request(subject, reason)
        return self._build_generic_request(subject, reason)

    def revoke(self, subject: RevocationSubject, reason: str) -> bool:
        if not self.enabled:
            return False
        target_url, payload, headers = self._build_provider_request(subject, reason)
        if not target_url:
            return False

        attempts = max(1, self.max_retries)
        for _ in range(attempts):
            try:
                resp = requests.post(target_url, json=payload, headers=headers, timeout=self.timeout_seconds)
                if 200 <= resp.status_code < 300:
                    return True
            except Exception:
                continue
        return False


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced IdP / JWT Capabilities
# ═══════════════════════════════════════════════════════════════════════════

def validate_jwt_claims(
    claims: dict[str, Any],
    required_issuer: str = "",
    required_audience: str = "",
    clock_skew_seconds: int = 30,
) -> tuple[bool, list[str]]:
    """Validate standard JWT claims (exp, nbf, iss, aud)."""
    errors: list[str] = []
    now = time.time()

    # Expiration
    exp = claims.get("exp")
    if exp is not None:
        try:
            if float(exp) + clock_skew_seconds < now:
                errors.append(f"Token expired at {exp}")
        except (ValueError, TypeError):
            errors.append(f"Invalid exp claim: {exp}")
    else:
        errors.append("Missing exp claim")

    # Not before
    nbf = claims.get("nbf")
    if nbf is not None:
        try:
            if float(nbf) - clock_skew_seconds > now:
                errors.append(f"Token not valid until {nbf}")
        except (ValueError, TypeError):
            errors.append(f"Invalid nbf claim: {nbf}")

    # Issuer
    if required_issuer:
        iss = str(claims.get("iss", ""))
        if iss != required_issuer:
            errors.append(f"Issuer mismatch: expected={required_issuer} got={iss}")

    # Audience
    if required_audience:
        aud = claims.get("aud", "")
        if isinstance(aud, list):
            if required_audience not in aud:
                errors.append(f"Audience {required_audience} not in {aud}")
        elif str(aud) != required_audience:
            errors.append(f"Audience mismatch: expected={required_audience} got={aud}")

    return len(errors) == 0, errors


class TokenBlacklist:
    """Bounded FIFO token blacklist for revoked JWTs."""
    _MAX = 10000

    def __init__(self):
        self._blacklist: dict[str, float] = {}  # token_hash -> revoked_at

    def revoke(self, token_hash: str):
        self._blacklist[token_hash] = time.time()
        if len(self._blacklist) > self._MAX:
            oldest = sorted(self._blacklist, key=self._blacklist.get)[:len(self._blacklist) - self._MAX]
            for k in oldest:
                del self._blacklist[k]

    def is_revoked(self, token_hash: str) -> bool:
        return token_hash in self._blacklist

    def count(self) -> int:
        return len(self._blacklist)

    def clear(self):
        self._blacklist.clear()


class OIDCDiscoveryCache:
    """Cache OIDC discovery documents with TTL."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = max(60, ttl_seconds)
        self._cache: dict[str, tuple[float, dict]] = {}

    def get(self, issuer_url: str) -> dict | None:
        entry = self._cache.get(issuer_url)
        if entry and (time.time() - entry[0]) < self.ttl:
            return entry[1]
        return None

    def set(self, issuer_url: str, discovery: dict):
        self._cache[issuer_url] = (time.time(), discovery)

    def invalidate(self, issuer_url: str = ""):
        if issuer_url:
            self._cache.pop(issuer_url, None)
        else:
            self._cache.clear()

    def fetch_and_cache(self, issuer_url: str) -> dict | None:
        """Fetch .well-known/openid-configuration and cache."""
        cached = self.get(issuer_url)
        if cached:
            return cached
        url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                doc = resp.json()
                self.set(issuer_url, doc)
                return doc
        except Exception:
            pass
        return None


class SessionBindingVerifier:
    """Verify JWT is bound to the presenting session/client."""

    def __init__(self):
        self._bindings: dict[str, dict] = {}  # jti -> {session_id, client_ip, user_agent}

    def bind(self, jti: str, session_id: str, client_ip: str = "", user_agent: str = ""):
        self._bindings[jti] = {"session_id": session_id, "client_ip": client_ip, "user_agent": user_agent}

    def verify(self, jti: str, session_id: str, client_ip: str = "", user_agent: str = "") -> tuple[bool, str]:
        binding = self._bindings.get(jti)
        if not binding:
            return True, "no_binding"  # first presentation
        if binding["session_id"] != session_id:
            return False, f"session_mismatch: bound={binding['session_id']} presented={session_id}"
        if binding["client_ip"] and client_ip and binding["client_ip"] != client_ip:
            return False, f"ip_mismatch: bound={binding['client_ip']} presented={client_ip}"
        return True, "ok"

    def clear(self):
        self._bindings.clear()


class MultiIdpFederation:
    """Support multiple IdP providers with priority routing."""

    def __init__(self):
        self._providers: dict[str, IdpRevocationClient] = {}
        self._priority: list[str] = []

    def register(self, name: str, client: IdpRevocationClient, priority: int = 0):
        self._providers[name] = client
        self._priority.append(name)
        self._priority.sort(key=lambda n: priority)

    def revoke_all(self, subject: RevocationSubject, reason: str) -> dict[str, bool]:
        """Revoke across all registered IdPs."""
        results = {}
        for name in self._priority:
            client = self._providers[name]
            results[name] = client.revoke(subject, reason)
        return results

    def get_provider(self, name: str) -> IdpRevocationClient | None:
        return self._providers.get(name)

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())
