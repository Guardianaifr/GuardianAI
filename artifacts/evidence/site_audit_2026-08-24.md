# frontend/site Audit — 2026-08-24

**Scope:** the 11-page static site at `frontend/site/` (served by FastAPI at `/site`), audited prior to building the replacement site in `website/`.
**Method:** three parallel read-only audit passes — (A) marketing-claims truth audit against repo artifacts, (B) security review with backend contract cross-check, (C) technical hygiene/link-graph review. Load-bearing figures re-verified firsthand by the lead agent (metering.py, `definitive_benchmark_v4.json`, `perf_chaos_report.json`, README validation snapshot, SDK surface).
**Disposition (owner decision, 2026-08-24):** old site left **byte-for-byte untouched**; all findings below remain OPEN. The new `website/` build carries corrected figures only.

---

## Overall verdict

The site leaks no secrets and publishes none of the retracted benchmark numbers, but it is **not safe to expose publicly today**: it contains three stored DOM-XSS paths, a JWT-in-URL WebSocket pattern with an infinite reconnect loop, and five core product flows that are broken against the live API (login on 3 of 4 pages, threat feed auth, logout, checkout→license issuance). It also publishes **7 outright false claims**, including both paid tier prices and three "Monad mainnet" statements contradicted by the code.

---

## A. Claims truth audit — 64 claims evaluated, 22 flagged

### A1. FALSE (7)

| # | Location | Published claim | Ground truth |
|---|---|---|---|
| F1 | `frontend/site/pricing.html:285` | Starter **$299/mo** | `backend/metering.py:57-73` implements Starter at **$49/mo** |
| F2 | `frontend/site/pricing.html:301` | Pro Gateway **$999/mo** | `backend/metering.py:74-92` implements Pro at **$299/mo** |
| F3 | `frontend/site/pricing.html:381,393` | "Cortex Pro $149/mo" + working checkout button (`checkout('cortex_pro')`) | Plan does not exist server-side; `backend/routers/billing_routes.py:29` VALID_PLANS rejects it → checkout returns 400 |
| F4 | `frontend/site/pricing.html:386` | "Monad **mainnet** anchoring (daily Merkle roots)" | `guardian/cortex/merkle_anchor.py:31` points at Monad **testnet** RPC; default mode is `simulated` (`:374`) |
| F5 | `frontend/site/pricing.html:431` | Comparison cell: "Pro: **Mainnet**" | Same as F4 — testnet |
| F6 | `frontend/site/pricing.html:479` | "Mainnet anchoring is available on Pro and Enterprise plans." | False, and self-contradicts line 444 ("testnet beta") on the same page |
| F7 | `frontend/site/audit.html:162` | Deep scan "**49 vectors** · ~5min" | Actual census in `guardian/audit/crypto_scanner.py` = **51** DEEP vectors (QUICK=10, STANDARD=26); pillar cards at `audit.html:208-213` also sum to 49 ≠ 51 |

### A2. OVERSTATED / contradictory (6)

| # | Location | Issue |
|---|---|---|
| O1 | `index.html:627`, `docs.html:325-326` | "Monad L1 on-chain anchoring" present-tense — pipeline defaults to simulated mode; cortex UI itself shows "SIMULATED — not yet on-chain" (`cortex.html:871`) |
| O2 | `pricing.html:337,344` | "anchored on Monad for $0.0001/tx … exists forever" — present tense for a simulated-by-default pipeline |
| O3 | `pricing.html:444` | "Mainnet deployment planned Q3 2026" — no such roadmap entry exists anywhere (only the Q3 2026 pentest re-review in `artifacts/evidence/external_pentest_status.md`) |
| O4 | `pricing.html:385-387` | "90-day rolling event retention" (no retention config found) + "Base L2 secondary anchoring" sold as live (only Base Sepolia testnet cleared) |
| O5 | `docs.html:331` vs `pricing.html:387` | Docs say multi-chain adapters are future work while pricing sells Base anchoring today — internal contradiction |
| O6 | `index.html:894` | "PDF evidence reports for SOC2 and GDPR compliance audits" — module produces EU AI Act artifacts; SOC2/GDPR are only hedged as "supporting evidence" elsewhere |

### A3. UNVERIFIABLE / puffery (6)

"the world's first system…" (`pricing.html:337`) · Monad 10,000 TPS / sub-second finality presented as own claim (`pricing.html:344,458`, `docs.html:326`) · "**100% resilient** de-obfuscation" (`docs.html:150`) · "**61+ Zero-Day Threat Patterns**" (no enumerable list) · "**18+ high-fidelity heuristics**" (count unlocatable) · tar-pit "45 seconds" exact figure.

### A4. Clean results

- **Retracted figures:** zero occurrences of 93.6% / 97.0% jailbreak / 98.4% zero-day / GAIA metrics across all pages.
- **Secrets/addresses:** no keys, no full contract addresses (only an obviously synthetic demo key), no internal IPs beyond a localhost health-check example, no trackers.
- **Correctly stated:** six-pillar scanner mapped to OWASP LLM Top 10 (10/10 per ROADMAP), ERC-5192 soulbound passport, interlock proofs, insurance copy describes signed evidence certificates only (no payout promises), Cortex 10-day trial mechanics match `cortex_routes.py`.
- **Risky items:** fabricated demo data renders unlabeled when APIs are empty (fake leaderboard incl. "trading-bot-alpha 96.2 DIAMOND", fake trust score card — `passport.html:543-557,617-631`); passport credential wording "Meets EU AI Act Article 15 requirements" reads certification-like (`passport.html:371`).

---

## B. Security findings

### P0 (exploitable / data-leak patterns)

- **P0-1 Stored DOM-XSS, dashboard/index event feed.** `index.html:1195-1205`, `dashboard.html:528-538` interpolate WS/fetch event fields (`details.path/pattern/message`) into innerHTML with no escaping. Event details derive from proxied request traffic → any external attacker who sends an HTML-bearing request path gets it persisted (`security_events`) and rendered raw into an authenticated admin's feed. Amplified by backend CSP allowlisting **all of jsDelivr** (`main.py:1188`), which lets `<script src="https://cdn.jsdelivr.net/npm/<attacker-pkg>">` execute despite nonces.
- **P0-2 Stored DOM-XSS, passport/history.** `passport.html:608` renders attacker-chosen passport `metadata.name` raw into the public leaderboard; `passport.html:655,664-675` render verify inputs/warnings raw; `history.html:641,704-726` render user-submitted scan `target_name`/`target_url` raw. (`leaderboard.html` and `audit.html` do escape correctly — the helper exists but isn't shared.)
- **P0-3 JWT in WebSocket URL + infinite reconnect.** `index.html:1290` puts the access token in `?token=`; `index.html:1302` reconnects every 3 s unconditionally. Tokens in URLs leak to logs/proxies/history; the loop retries forever because of P1-1.

### P1 (broken contracts / high risk)

| # | Finding | Evidence |
|---|---|---|
| P1-1 | Live threat feed dead on BOTH dashboards: backend requires first-message `{"token":…}` within 10 s; dashboard.html sends nothing, index.html uses query string | `dashboard_routes.py:487-520` vs `dashboard.html:585`, `index.html:1290` |
| P1-2 | Login broken on index/dashboard/passport — pages POST JSON bodies; API requires HTTP Basic (only cortex.html does it right) | `auth_routes.py:102-164` vs `index.html:1004`, `dashboard.html:357`, `passport.html:399` |
| P1-3 | Logout POSTs nonexistent `/api/v1/auth/logout`; only form-flow GET /logout exists; token never blacklisted | `index.html:1029`, `dashboard.html:382`; `auth_routes.py:816-823` |
| P1-4 | Purchase flow dead end-to-end: checkout requires auth the anonymous page doesn't send (401); success-page license confirm/issue require **admin** (403 for paying customer) | `billing_routes.py:65-66,124,144` vs `app.js:63-67`, `success.html:91,103` |
| P1-5 | Badge `<img src=…/api/v1/audits/{id}/svg>` can never authenticate → all badge images 401 | `audit_routes.py:45-47` vs `index.html:1164`, `dashboard.html:497` |
| P1-6 | leaderboard.html fetches wrong endpoints without auth → permanently empty; purpose-built `GET /api/v1/leaderboard` exists and is never called | `leaderboard.html:145-146`; `scan_routes.py:236` |
| P1-7 | history.html expects array/`.history`; API returns `{scans,trend,total}` → ledger always empty | `history.html:608-617` vs `scan_routes.py:186+` |
| P1-8 | Backend CSP/XFO breaks the site itself: `frame-ancestors 'none'` blocks the dashboard's five same-origin iframe pages; inline `onclick=` handlers blocked by script-src without unsafe-inline; Google Fonts domains absent from style-src/font-src → fonts silently fall back | `main.py:1157-1197`; `index.html:807-824` |
| P1-9 | Hardcoded Basic-auth password fallbacks `'admin'` / `'guardian_default'` shipped client-side; after reload, requests send guessed passwords | `dashboard.html:416,509`; `index.html:1083,1176` |

### P2 (hygiene)

Unpinned CDN dep with no SRI (`chart.js` via bare jsDelivr URL, 3 pages) · tokens in localStorage with no expiry handling (prefer the existing HttpOnly-cookie flow + CSRF support) · no `Cache-Control: no-store` on authenticated responses · open-redirect-shaped sink `window.location.href = out.checkout_url` unvalidated · `prompt()`-based credential prompts defaulting username to `admin` + hardcoded junk PII `security@example.com` on orders (`pricing.html:496,513`) · assorted minor unescaped sinks of server-generated data (`app.js:81-96,326`, `cortex.html:786,807`, `audit.html:314,345`) · internal port disclosure in public docs copy (`docs.html:308`).

**Secrets sweep:** clean (no `sk-`/Stripe keys/private keys/tracker IDs; Stripe cancel/success pages render no URL params into HTML).

---

## C. Hygiene findings

- **Navigation collapse:** six hand-duplicated nav menus with drift; dead anchors `index.html#workflow` (no such id) and `#pricing`; leaderboard.html orphaned (unlinked, missing Pricing item); footers on only 6 of 11 pages.
- **Duplication:** ~600-line console clone embedded in index.html duplicating dashboard.html (sidebar/login/apiFetch/WebSocket/Chart setup); `site-assets/app.js` referenced by zero pages (dead code); cortex.html abandoned the shared stylesheet entirely (fully inline).
- **Staleness:** split CSS cache-busters (`?v=20260602web3agent` ×7 vs stale `?v=20260514v4` ×3 → cached-CSS risk); "COMING SOON" badge on the fully-built Passport feature (`index.html:709`); dev placeholder text shipped (`cortex.html:376`).
- **A11y:** zero aria attributes across all 11 files; no h1 on cortex/dashboard/passport; placeholder-only labels on 3 inputs; keyboard-unreachable `<div onclick>` navs; footer contrast ≈2.3:1 fails AA.
- **SEO/perf:** no favicon, robots.txt, sitemap.xml, canonical, or OG tags anywhere; meta descriptions missing on docs/cancel/success; Chart.js loaded render-blocking in head on 3 pages (~200 KB).
- **Static-open behavior:** docs/pricing/cancel fully static; success/audit/leaderboard/history degrade to empty states; index marketing half fine but its console half requires backend; dashboard/passport/cortex require backend.

---

## D. Backend bugs the audit surfaced (code-level, independent of the site)

1. **Pricing inconsistency:** `backend/routers/billing_routes.py:45,51` public-plans advertises Starter $299 / Pro $999, while `backend/metering.py` charges $49/$299. Whichever page/API a customer sees first, one of them is wrong.
2. **Missing route:** no `POST /api/v1/auth/logout` although two frontends call it; JWT blacklist infrastructure exists but is unreachable from the API path used.
3. **WS auth contract:** `/ws/threats` requires first-message JSON auth, but neither shipped dashboard client implements it — the marquee live-threat-feed feature has likely never worked as deployed.

## E. Recommended remediation order (when old-site work is authorized)

1. Share one `escapeHtml()` helper and escape every interpolation (kills P0-1/P0-2).
2. First-message WS auth + bounded backoff + clear-token-on-1008 (P0-3/P1-1).
3. HTTP Basic login everywhere; real logout endpoint; billing flow auth model fixed (P1-2/3/4).
4. CSP: pin chart.js version + SRI or self-host; drop whole-domain jsDelivr allowance; add font-src/style-src entries; replace inline onclick handlers (P1-8, P2).
5. Truth patch: prices from metering.py, remove mainnet claims, fix vector count, soften overstated/unverifiable copy, label demo data.
6. Structural: single nav/footer partial, delete app.js dead code, dedupe console clone, favicon/sitemap/robots/OG, a11y pass.
