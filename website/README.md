# GuardianAI public website

Static, dependency-free marketing site. Four pages, plain HTML/CSS/vanilla JS,
no build step, no CDN JavaScript. Works when opened straight from disk
(`file://`) and deploys unchanged to any static host.

## Preview locally

1. From the repository root run: `python -m http.server 8090 --directory website`
2. Open http://localhost:8090 in your browser.

(Opening `index.html` directly also works; a local server is only nicer.)

## Pages

| File | Purpose |
|---|---|
| `index.html` | Hero, verified stat strip, dual-plane story, feature grid, proof highlights, pricing teaser |
| `how-it-works.html` | Off-chain request path (5 steps), on-chain trust path (4 steps), nine-contract suite, SDK integration snippet |
| `pricing.html` | The four tiers exactly as implemented in `backend/metering.py`, compliance honesty notes |
| `proof.html` | Benchmarks, performance/chaos, tests, audit status, chains & identity, privacy disclosures — each figure mapped to its artifact |

Shared assets: `css/style.css` (design system), `js/main.js` (~40 lines:
mobile nav, reveal-on-scroll, year stamp), `assets/logo.svg`,
`assets/favicon.svg`. Plus `sitemap.xml` and `robots.txt`.

## BEFORE DEPLOYING

- Replace the placeholder host `https://aiguardian.dev/` in **both**
  `sitemap.xml` and `robots.txt` with the real domain.
- Add `<link rel="canonical">` and `og:url` per page once the domain exists.
- SVG favicons are unsupported in older Safari; add a PNG favicon if that
  browser matters to you.

## Content rules for future editors (enforced at build time 2026-08-24)

Every published figure must trace to a named artifact — the mapping lives on
the proof page (`proof.html#sources`) and below. The prior site
(`frontend/site/`) shipped false claims caught by the 2026-08-24 audit
(see `artifacts/evidence/site_audit_2026-08-24.md`); do not reintroduce them:

| Published figure / claim | Source artifact |
|---|---|
| All benchmark block rates incl. totals (76.6%/58.5%), security-gate subset (97.6%/90.7% = 949/972, 882/972) | `artifacts/evidence/definitive_benchmark_v4.json` (run 2026-08-08) |
| False positives, fresh-session live run: balanced 11.2% (26/233), strict 29.2% (68/233), three public corpora | `artifacts/evidence/fp_clean_measure.json` |
| Throughput 95.68 req/s safe / 494.01 req/s attack-blocking, p95 41.88 ms, chaos outcomes, SLOs | `artifacts/performance/perf_chaos_report.json` (April 2026) |
| Test counts ERC-8004 42/42; targeted Python 107/107 passed; rate limiter 33/33 passed; Hardhat 160 cases/10 suites (100% pass) | `README.md` validation snapshot |
| Audit history (external pentest closed 2026-03-18; internal audits remediated Jul/Aug/Sep 2026; next external review Q3 2026) | `artifacts/evidence/security_signoff.md`, `WHITEPAPER.md §6.3` |
| Prices $0 / $49 / $299 / custom, all tier limits & features | `backend/metering.py` PRICING_TIERS |
| Anchoring simulated-by-default, Monad testnet opt-in; ERC-8004 mainnet registries = ecosystem infra; insurance = certificate anchoring only | `guardian/cortex/merkle_anchor.py`, whitepaper §6–7 |

**Never publish:** retracted figures (93.6%, 97.0%, 98.4%, GAIA metrics),
"Monad mainnet" anchoring claims, an "externally audited" present-tense claim,
contract addresses, keys, internal URLs/ports, or any figure without an
artifact row above.

**Pricing status (owner decision 2026-08-24):** hosted tiers are "coming
soon" — no prices are published anywhere on the site until a hosted gateway,
live metering, and checkout all exist. When that changes, prices come from
`backend/metering.py` only (never `billing_routes.py`, which advertises
different numbers — see the audit file).
