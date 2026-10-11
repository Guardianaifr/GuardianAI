"""Public deployment of the GuardianAI relay (Cloud Run, behind Firebase Hosting).

Serves the same GuardianRPCRelay that tools/run_relay.py runs locally, with a public-facing guard:

  * Only these routes are reachable. Everything else (the RPC proxy at "/", /rules, /whitelist,
    /stats, rule writes) returns 404, so the public URL is not an open RPC endpoint or admin API.
        GET  /health
        POST /api/v1/attest
        GET  /api/v1/agents/<agent_id>/rules
        GET  /api/v1/threat-oracle/feed      (read by the Chainlink CRE workflow)
  * Attestation requests are rate limited per client and globally. The global cap is the hard bound.
    The per-client key is the first X-Forwarded-For entry, which a client can forge, so it only slows
    down honest-but-busy clients. Waitress is told to keep that header (it strips it by default).
  * Bodies over 64 KB are refused.
  * CORS is off by default: aiguardian.dev reaches the relay same-origin through a Firebase Hosting
    rewrite. GUARDIAN_CORS_ORIGINS (comma separated) allows extra origins, e.g. http://localhost:5173.

Run:  python -m guardian.web3sec.cloud_relay        (listens on $PORT, default 8080)

Environment (see deploy/relay/README.md): GUARDIAN_ATTESTATION_SIGNER_KEY (required, from Secret Manager),
GUARDIAN_ENV=production, GUARDIAN_RELAY_ATTEST_PER_MIN, GUARDIAN_RELAY_ATTEST_GLOBAL_PER_MIN.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional

from flask import Flask, Response, request

logger = logging.getLogger("guardian.web3sec.cloud_relay")

MAX_BODY_BYTES = 64 * 1024

_PUBLIC_ROUTES = (
    ("GET", re.compile(r"^/health$")),
    ("POST", re.compile(r"^/api/v1/attest$")),
    ("GET", re.compile(r"^/api/v1/agents/[^/]{1,200}/rules$")),
    ("GET", re.compile(r"^/api/v1/threat-oracle/feed$")),
)


class SlidingWindowLimiter:
    """At most `limit` events per `window` seconds for each key. Thread-safe, memory bounded."""

    def __init__(self, limit: int, window: float = 60.0, max_keys: int = 50_000):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        cutoff = now - self.window
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self.max_keys:
                    self._evict(cutoff)
                q = self._hits[key] = deque()
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def _evict(self, cutoff: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]:
            del self._hits[k]
        if len(self._hits) >= self.max_keys:  # still full of active keys: drop the oldest
            oldest = min(self._hits, key=lambda k: self._hits[k][-1])
            del self._hits[oldest]


def _json(status: int, body: dict) -> Response:
    return Response(json.dumps(body), status=status, mimetype="application/json")


def client_key() -> str:
    """Best-effort client identity. Behind Google's front end the client address is in X-Forwarded-For."""
    xff = request.headers.get("X-Forwarded-For", "")
    first = xff.split(",")[0].strip() if xff else ""
    return first or (request.remote_addr or "unknown")


def _is_public(method: str, path: str) -> bool:
    return any(m == method and rx.match(path) for m, rx in _PUBLIC_ROUTES)


def _path_is_public(path: str) -> bool:
    return any(rx.match(path) for _, rx in _PUBLIC_ROUTES)


def install_public_guard(
    app: Flask,
    per_client_per_min: int = 30,
    global_per_min: int = 120,
    cors_origins: Optional[set] = None,
) -> None:
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    per_client = SlidingWindowLimiter(per_client_per_min)
    overall = SlidingWindowLimiter(global_per_min)
    origins = {o.rstrip("/") for o in (cors_origins or set()) if o}

    @app.before_request
    def _guard():
        method, path = request.method, request.path
        if method == "OPTIONS":
            origin = request.headers.get("Origin", "").rstrip("/")
            if origin in origins and _path_is_public(path):
                return Response(status=204)
            return _json(404, {"error": "Not found"})
        if not _is_public(method, path):
            return _json(404, {"error": "Not found"})
        if request.content_length and request.content_length > MAX_BODY_BYTES:
            return _json(413, {"error": "Request body too large"})
        if path == "/api/v1/attest":
            if not overall.allow("global"):
                return _json(429, {"error": "GuardianAI is busy. Try again in a minute."})
            if not per_client.allow(client_key()):
                return _json(429, {"error": "Too many approval requests from this client. Try again in a minute."})
        return None

    @app.after_request
    def _cors(resp: Response):
        origin = request.headers.get("Origin", "").rstrip("/")
        if origin and origin in origins and _path_is_public(request.path):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
            resp.headers["Access-Control-Max-Age"] = "600"
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        return resp


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except ValueError:
        return default


def create_app() -> Flask:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    # Secret Manager values created on Windows often end in a newline; the key parser rejects that.
    key = os.environ.get("GUARDIAN_ATTESTATION_SIGNER_KEY", "").strip()
    if key:
        os.environ["GUARDIAN_ATTESTATION_SIGNER_KEY"] = key
    if not key:
        # Without it the relay would sign with a throwaway key that every contract rejects.
        raise RuntimeError("GUARDIAN_ATTESTATION_SIGNER_KEY is not set")
    if os.environ.get("GUARDIAN_DEPLOYER_PRIVATE_KEY"):
        # The public relay never needs the deployer key; refuse to run with it in the environment.
        raise RuntimeError("Do not give the public relay GUARDIAN_DEPLOYER_PRIVATE_KEY")

    from guardian.web3sec.rpc_relay import GuardianRPCRelay

    relay = GuardianRPCRelay({"web3_security": {"listen_port": int(os.environ.get("PORT", 8080))}})
    if relay.attestation_service is None or getattr(relay.attestation_service, "ephemeral_signer", True):
        raise RuntimeError("Attestation service failed to start with the configured signer key")

    cors = {o.strip() for o in os.environ.get("GUARDIAN_CORS_ORIGINS", "").split(",") if o.strip()}
    install_public_guard(
        relay.app,
        per_client_per_min=_env_int("GUARDIAN_RELAY_ATTEST_PER_MIN", 30),
        global_per_min=_env_int("GUARDIAN_RELAY_ATTEST_GLOBAL_PER_MIN", 120),
        cors_origins=cors,
    )
    relay.app.extensions["guardian_relay"] = relay
    logger.info("Public relay ready: signer %s, CORS %s", relay.attestation_service.signer_address, sorted(cors) or "off")
    return relay.app


def serve() -> None:
    """Production server: waitress on 0.0.0.0:$PORT, keeping X-Forwarded-For for the per-client limit."""
    import signal
    import sys

    from waitress import serve as waitress_serve

    # PID 1 in a container ignores SIGTERM unless handled; Cloud Run sends it before stopping an instance.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    waitress_serve(
        create_app(),
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
        threads=8,
        clear_untrusted_proxy_headers=False,
    )


if __name__ == "__main__":
    serve()
