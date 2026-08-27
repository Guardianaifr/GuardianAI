# GuardianAI — Senior Full Audit Report
**Date:** 2026-08-20 · **Scope:** entire repository at `f5b77db4` · **Method:** read-only review (no changes made)

Areas covered: backend API (auth, JWT, RBAC, rate limiting, all 14 routers), interceptor core (pipeline, language allowlist, F27/F2 fixes, output assurance), web3/Solidity (9 contracts, RPC relay, breaker), test suite, docs-vs-code, infra/hygiene, CI. Severity: P0 critical → P3 low.

---

## Executive summary

The security hardening work from Phases 1–5 and the F-series fixes is **real and holds up under review**: Argon2id, hardened JWT verification, fail-closed rate limiting, CSRF, CSP/nonce, 1MB body limit, WebSocket first-message auth, tenant scoping, the F27 abstain-bypass fix, and the language-allowlist raw-body gating are all verified in code with regression tests that are legitimate (not vacuous). The whitepaper's Section 6 benchmark numbers now match the evidence file exactly, with an honest correction section.

However, this audit found **one P0** that invalidates the security posture of any deployment using the shipped config, plus a set of P1s: the interceptor's admin/bypass token is committed to the repo and is the key that turns off every protection; it is also written to logs on failed admin bypasses. The RPC relay still forwards undecodable transactions by default (`fail_mode: open`), and its management endpoints have no authentication. A second, fully-wired auth system (`auth.py` AuthManager + `rbac.py`) turned out to be dead code that contradicts the "dual-layer security" comment in `main.py`. Infra findings include a compose volume that does not actually persist the database and two unbuildable secondary Dockerfiles.

**Top 3 attack chains:**
1. **Repo reader → total bypass.** The committed `admin_token` (config.yaml:338) + `X-Guardian-Role: admin` + `X-Guardian-Token` (interceptor.py:1769–1779) skips every check and is audited only as an "admin_action" event. The same token opens `/debug/info` (interceptor.py:540) which serves stored full request headers (including bearer tokens) and prompts.
2. **Local process → relay disarm.** Unauthenticated `POST /rules` / `POST /whitelist` on the relay (rpc_relay.py:104–108) disables all detectors or whitelists an attacker address; combined with `fail_mode: open`, an EIP-4844/7702 typed transaction (not handled by the decoder, lines 35–55) is forwarded unaudited.
3. **Log reader → credential harvesting.** interceptor.py:1781 logs `ConfigToken={admin_token}` on every failed admin bypass; debug info holds bearer tokens in memory.

---

## P0 — Critical

### P0-1. Live admin/bypass token committed to git
- `guardian/config/config.yaml:338` — `security_policies.admin_token: 793c3aae07657...` (64-hex)
- `guardian/config/wizard_config.yaml:34` — `admin_token: du1xFyvMpKoGvTj_...` (43-char)
- Introduced in commit `12a14bfe` ("temp commit for test verification"); still at HEAD; recoverable from history.
- This token is **live auth** in three places:
  - Interceptor admin routes: `Authorization: Bearer <admin_token>` (guardian/runtime/interceptor.py:258)
  - Proxy auth: accepted as `X-Guardian-Token` (interceptor.py:1575)
  - **Full security bypass**: `X-Guardian-Role: admin` + token skips the entire guardrail chain (interceptor.py:1769–1784)
- Remediation: rotate both tokens, move to env/ignored runtime config, `git filter-repo`/BFG history purge (pair with P1-9), then verify no other copies (tests, scans/) reference the rotated values.

---

## P1 — High

### P1-1. Admin token logged on failed bypass
`guardian/runtime/interceptor.py:1781` — `logger.warning(f"ADMIN FAIL: ... ConfigToken={admin_token}, ReqToken={request_token}")` writes the live admin token to logs on every failed admin-bypass attempt. Fix: log a hash/prefix only. (Related P3: line 1770 compares tokens with `==` instead of `secrets.compare_digest` — inconsistent with lines 1573/1575.)

### P1-2. Raw-tx decode gap still open by default (known issue confirmed)
`guardian/web3sec/rpc_relay.py:76` — `fail_mode` defaults to `"open"`, so a raw transaction that fails to decode is **forwarded as-is** (line 284). The decoder only handles legacy + typed `0x01`/`0x02` envelopes (lines 35–55); EIP-4844 (0x03) and EIP-7702 (0x04) transactions raise → decode fails → pass-through. All detectors bypassed. Fix: default `fail_mode: closed`, add typed-tx support, and handle `params == []` (currently `if not tx: return None` passes through silently).

### P1-3. Relay management endpoints unauthenticated
`rpc_relay.py:104–108, 196–255` — `POST /rules`, `POST /whitelist`, `DELETE /whitelist/<addr>` have no auth. Any local process (or SSRF from a dev-mode backend, see P2-7) can disable every detector or whitelist attacker addresses. Loopback-only binding (line 388) is the sole mitigation. Fix: require the admin token (constant-time) on management routes.

### P1-4. Second auth layer is dead code contradicting the "dual-layer" claim
- `backend/auth.py` `AuthManager` (users, token pairs, revocation) and `backend/rbac.py` (role matrix, `require_permission`/`require_role`/`get_current_user_from_token`) are wired to **zero routes**. Only `VALID_ROLES` is imported (auth.py:332).
- `backend/main.py:377–380` claims both systems are "maintained for dual-layer security" — false as written.
- Latent hazard if ever wired: main.py-issued tokens (role `admin`, no `type` claim) would be accepted by the rbac path as an **access** token because auth.py:501 defaults `type→"access"` and `_jwt_decode` does not check `iss`. Same signing secret, different claim schemas.
- Per your remove-over-wire doctrine: either remove auth.py's AuthManager + rbac.py (keeping hash/verify password utils), or wire them properly — and fix the comment either way.

### P1-5. docker-compose does not persist the database
`docker-compose.yml:33-34` mounts `./guardian_data:/app/data`, but `backend/main.py:345` hardcodes `DB_PATH = "guardian.db"` (relative → `/app/guardian.db`). All tenant/scan data is lost on container recreation. Fix: env-driven `DB_PATH` pointing into `/app/data`.

### P1-6. Secondary Dockerfiles broken and root-running
`backend/Dockerfile` and `guardian/Dockerfile` `COPY requirements.txt .` — that file doesn't exist in either directory; both are unbuildable (never tested) and have no `USER` directive. Delete or repair.

### P1-7. node_modules committed to git (~17,900 files)
`node_modules/**` + `contracts/node_modules/**` ≈ 93% of tracked files; pack is 230.71 MiB. Untrack and gitignore.

### P1-8. Gitignore gaps make hygiene regression one `git add .` away
40+ root scratch files (debug_*, out_*, diff_*, probe_*, traceback*, payload_*.json, temp2.sol, *.vsix, …) are untracked but **not ignored** — a single `git add .` re-commits ~15 MB of junk. Add patterns before next commit.

### P1-9. Sensitive files remain in git history
`guardian.db`, `web3sec_blocked.db`, `payload.json`, debug outputs were committed in `b2df1979` and removed only from HEAD (`e0c48eea`) — still recoverable. Purge history in the same rewrite as the P0 token rotation; inspect historical `guardian.db` for tenant data before deciding on disclosure obligations.

---

## P2 — Medium

| # | Finding | Evidence |
|---|---------|----------|
| P2-1 | "Encryption" of agentic key secrets is static-keystream XOR derived from `AGENTIC_ATTESTATION_SECRET` (which defaults to `JWT_SECRET`) — deterministic, no nonce, no key separation; anyone with DB read + secret decrypts all agent keys | backend/main.py:2321–2342, 312 |
| P2-2 | Streaming (SSE) responses bypass robust output scanning: response buffered whole, then regex'd as raw SSE text; PII/harm split across deltas evades; also breaks streaming semantics | interceptor.py:1899–1917 |
| P2-3 | OutputAssuranceGuard (F27) ships **disabled** (`config.yaml:261 enabled: false`); fix verified solid but off by default — ensure whitepaper/docs don't overstate | config.yaml:250–263 |
| P2-4 | Public `/api/v1/scan/leaderboard` exposes customer scan targets/scores without auth | scan_routes.py:237 |
| P2-5 | Relay whitelist check runs **before** detectors; a whitelisted `from` address bypasses all transaction analysis; `detector.enabled` mutated per-request (thread race under waitress threads=8) | rpc_relay.py:291–305 |
| P2-6 | SSRF monkey-patch disabled whenever `GUARDIAN_ENV=development` — which is the **default**; default deployments allow private-IP egress; no allowlist path for internal audit sinks in prod | main.py:26, 39 |
| P2-7 | `_validate_basic` supports plaintext-password compare path; unknown-user vs known-user timing asymmetry enables username enumeration | main.py:1265–1277 |
| P2-8 | JWT `aud` validation one-sided: tokens without `aud` pass when `GUARDIAN_JWT_AUDIENCE` set; `create_token_pair` never emits `aud`/`iss` (moot while AuthManager is dead — fix if revived) | auth.py:162–172, 448–468 |
| P2-9 | auth.py's ephemeral-secret fallback (auth.py:48) only warns; not gated on production the way main.py:327 is |
| P2-10 | Vault reference impl credits balance **before** `safeTransferFrom` (deposit) — unsafe pattern for hook-tokens in a template integrators copy | GuardianProtectedVault.sol:49–54 | ✅ **FIXED** |
| P2-11 | Forwarded request copies client cookies + `X-Guardian-Token` to upstream | interceptor.py:1889–1896 |
| P2-12 | Compose publishes admin dashboard on 0.0.0.0 (docs claim 127.0.0.1); no HEALTHCHECK; `--allow-risky-ports` baked into image entrypoint; nginx.conf orphaned (referenced nowhere) with dead TLS block | docker-compose.yml:9-11, Dockerfile:75, nginx/ |
| P2-13 | PII engine documented-degraded: presidio 2.2.361 cannot import (pydantic v1 chain); PII detection silently falls back to regex — release risk for a security product | requirements.txt:31–44 |
| P2-14 | Dependency sprawl: 3 orphaned, conflicting lock files (one UTF-16LE-encoded); no canonical lock | requirements-*.txt |
| P2-15 | Relay code coverage 16%, monitor 24% — the web3sec hot paths are barely tested | pytest coverage report |
| P2-16 | `agentic_attestation` debug/info route holds full request headers (bearer tokens) and prompts in memory; admin-gated, but compounds P0-1 | interceptor.py:525–540, 1685–1695 |

---

## P3 — Low
- Non-constant-time `==` on admin bypass (interceptor.py:1770).
- Abstain detection: refusal-regex matches anywhere in text — "I cannot stress this enough: <harm>" reads as abstention; only skips the citation-conflict block (output_assurance.py:47–66, 236).
- Bare `from guardrails.` imports rely on sys.path bootstrap (guardian/main.py:67, guardrails/input_filter.py:52) — fragile if imported as package from elsewhere.
- langdetect failure → allowlist skipped (documented as policy control, acceptable; interceptor.py:1509–1511).
- `revokeCertificate` is `whenNotPaused` — cannot revoke during an incident pause (GuardianInsuranceLedger.sol:118).
- CSP allows `cdn.jsdelivr.net` scripts and `unsafe-inline` styles; nonce injection regex is fragile (main.py:1163–1176).
- CI: `redis_rate_limit.yml` on Python 3.11 vs project 3.12; supply-chain gate signs with hardcoded demo key; no Docker build job in CI; local dev runs Python 3.14 vs Docker 3.12 (confection warns).
- ~~Breaker hardcodes chain `"monad"` in attestation lookups (GuardianCircuitBreaker.sol:98, 121).~~ **(FIXED: Parameterized via constructor and `GUARDIAN_CHAIN_NAME` env var)**
- Base images not digest-pinned; `./artifacts` host-mount into container; `DEPLOYMENT.md` port claims and "61/61 tests" stale.
- Three near-identical whitepaper variants (`WHITEPAPER.md`, `_PUBLIC`, `Update`) — maintenance drift risk; keep one canonical source.
- Tracked third-party-target scan artifacts (`scans/new scan.txt` vs polymarket.com, `artifacts/audit/agentlove_*.html`) — legal/reputational exposure; remove.
- API-key hash uses `JWT_SECRET` as pepper — rotating the JWT secret invalidates all API keys (operational coupling).

---

## Verified as solid (prior work that holds)

**Backend:** Argon2id (t=7,m=64MB,p=4) with production refusal to fall back to SHA-256 · JWT decode checks alg before signature, constant-time compare, exp/nbf/aud · jti revocation + refresh rotation · auth lockout (3-tier redis/sqlite/memory) · rate limiter fail-closed (503) with Redis sliding-window Lua · CSRF double-submit cookie · security headers + CSP nonce · HTTPS enforcement · 1MB body limit · WS first-message auth (10s timeout, admin/auditor only, fail-closed) · tenant scoping on analytics/telemetry/cortex/passport (checked individually) · `scan_id` validated before path/subprocess use (scan_routes.py:109/134) · SQL parameterized throughout (the two f-string SQL sites generate only `?` placeholders — misc_routes.py:471/517) · API keys stored as peppered SHA-256, looked up by hash · upstream-key injection replaces client credentials · ProxyFix with explicit trusted-hops; XFF spoofing not possible by default · billing confirm/license issue admin-gated · token minting derives role from the authenticating user (no escalation).

**Interceptor:** pipeline ordering sound (rate limit → auth (fail-closed default) → tenant → multimodal/RAG/agentic → prompt extraction with raw-body fallback (non-dict JSON no longer crashes to bypass) → obfuscation decode → quarantine/memory/brain gates → language allowlist (correctly skipped for raw bodies, which still get full scans) → trust exploitation → keyword → base64-entropy → threat feed → fast-path blocklist → AI firewall → adaptive actions). F27 abstain fix genuine (flag alone insufficient; answer text must match refusal patterns). F2 translation adapter wired (ai_firewall.py:55). The raw-body regression tests are legitimate — they assert the body reaches `check_prompt`, not that the check passes.

**Contracts:** InsuranceLedger — cap (100k) enforced on the only write path with sensible check ordering; no ETH flows; Ownable2Step+Pausable+ReentrancyGuard. Timelock — standard OZ controller, 24h min delay, documented open-executor rationale. CircuitBreaker — clean modifiers, documented fail-open/fail-closed variants.

**Tests/docs:** 1,416 tests collect with zero errors; previously-red `test_upstream_health_caching` now passes; the c0e1d413 stub concern is a false alarm (the stub is the seam under test). Whitepaper Section 6 matches `definitive_benchmark_v4.json` exactly (76.2% strict = 2,448/3,211; Tier1+2 97.1% = 944/972 ✓) with a transparent §6.2 correction of the prior synthetic-fixture numbers; the three variants are mutually consistent. Full suite not run in this audit (CI runs it); one file spot-run green (6/6).

---

## Recommended fix order (one at a time, per your workflow)
1. **P0-1** rotate + scrub admin tokens (with history purge P1-9 in the same rewrite).
2. **P1-1** stop logging the admin token.
3. **P1-2** relay `fail_mode: closed` default + typed-tx decode (or explicit reject).
4. **P1-3** auth on relay management endpoints.
5. **P1-4** remove-or-wire decision for auth.py/rbac.py + fix the dual-layer comment.
6. **P1-5/6/7/8** compose DB path, Dockerfiles, node_modules, gitignore — then re-run hygiene validation.
7. P2s in table order (P2-1 agentic crypto and P2-2 SSE scanning first).
