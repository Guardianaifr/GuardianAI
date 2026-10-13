# GuardianAI public website (aiguardian.dev)

Static site, plain HTML/CSS/vanilla JS, no build step for the marketing pages. Deployed to Firebase Hosting
(`firebase.json` at the repo root, hosting target `guardian-target` → site `aiguardian-site`).

## Preview locally

1. From the repository root run: `python -m http.server 8090 --directory website`
2. Open http://localhost:8090 in your browser.

Firebase's `cleanUrls` and the `/explorer` and `/mera` rewrites only apply on Firebase; locally, open
`/explorer/index.html` and `/mera/index.html` directly.

## Pages

| Path | What it is |
|---|---|
| `index.html` | Home: hero, verified stat strip, dual-layer story, live integrations |
| `how-it-works.html` | Off-chain request path, on-chain trust path, contract suite, SDK snippet |
| `proof.html` | Benchmarks, performance/chaos, tests, audit status, chains and identity, privacy disclosures; every figure mapped to its artifact |
| `docs.html` | Developer documentation page (`css/docs.css`, `js/docs.js`) |
| `explorer/` | **Attack Lab** (`/explorer/`) and **Console** (`/explorer/?view=console`). Production build of `dashboard/` (Vite); do not edit by hand |
| `mera/` | Mera operator passkey console (`/mera/`). Source and tests in `metropolis/mera/` |

Shared assets: `css/style.css` (design system), `js/main.js` (mobile nav, reveal-on-scroll, year stamp),
`assets/` (logo, favicons incl. PNG fallbacks). Plus `sitemap.xml` and `robots.txt`.

## Updating the explorer build

```bash
cd dashboard
npm install
npm run build          # writes dashboard/dist/
```

Then replace `website/explorer/index.html` and `website/explorer/assets/` with the contents of
`dashboard/dist/` (keep `website/explorer/screenshots/` and `guardian-logo.svg`). Vite is configured with
`base: './'`, so the build works under `/explorer/`.

## Deploy

```bash
firebase deploy --only hosting
```

`netlify.toml` and `vercel.json` are kept so the folder also deploys unchanged to Netlify or Vercel (same
security headers). `.github/workflows/deploy-pages.yml` can publish to GitHub Pages but is manual-only, as
Pages is not enabled for the repo.

## Content rules for future editors

Every published figure must trace to a named artifact; the mapping lives on the proof page
(`proof.html#sources`) and below. The earlier site (`frontend/site/`, still served by the backend at `/site`) shipped false claims
caught by the 2026-08-24 audit (see `artifacts/evidence/site_audit_2026-08-24.md`); do not reintroduce them.

| Published figure / claim | Source artifact |
|---|---|
| All benchmark block rates incl. totals (76.6%/58.5%), security-gate subset (97.6%/90.7% = 949/972, 882/972) | `artifacts/evidence/definitive_benchmark_v4.json` (run 2026-08-08) |
| False positives, fresh-session live run: balanced 11.2% (26/233), strict 29.2% (68/233), three public corpora | `artifacts/evidence/fp_clean_measure.json` |
| Throughput 95.68 req/s safe / 494.01 req/s attack-blocking, p95 41.88 ms, chaos outcomes, SLOs | `artifacts/performance/perf_chaos_report.json` (April 2026) |
| Test counts: Hardhat 271 (15 suites), Python 1,490+, Mera 26 Vitest + 166 hard-audit assertions | Repository `README.md` test table (re-run October 2026) |
| Audit history (external pentest closed 2026-03-18; internal audits remediated Jul/Aug/Sep 2026) | `artifacts/evidence/security_signoff.md`, `docs/whitepaper/WHITEPAPER_PUBLIC.md §6.3` |
| Anchoring simulated by default, Monad testnet opt-in; ERC-8004 mainnet registries = ecosystem infra; insurance = certificate anchoring only | `guardian/cortex/merkle_anchor.py`, whitepaper §6–7 |
| Live integrations (agent wallet, CRE oracle, Envio, Privy, ElizaOS, Mera) and their transactions | `metropolis/README.md` |

**Never publish:** retracted figures (93.6%, 97.0%, 98.4%, GAIA metrics), "Monad mainnet" claims, an
"externally audited" present-tense claim, private keys, internal URLs/ports, or any figure without
an artifact row above. Monad **testnet** contract addresses and transactions may be published, linked to
MonadScan, as the README does.
