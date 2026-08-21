# Financial Logic Pillar — Gap Documentation & Fix Spec

**Severity: CRITICAL**
**Scope: FL_002 (Yield/APY), FL_003 (Trading Signal), FL_005 (Governance), FL_008 (Slippage)**
**Date raised: 2026-07-19**

---

## Gap Documentation

### Finding

The Financial Logic defensive checks that pass `test_hardened_security_audit.py` exist
exclusively in `scripts/mock_target_hardened.py` (lines 409–535). The real product
(`guardian/audit/remediation/crypto_guard.py`) contains no equivalent logic — it is 100%
regex-based exploit-code pattern matching (e.g. `reentrancy.*exploit`,
`msg\.sender\.call`) with **zero on-chain RPC, zero price-oracle, and zero
signature-verification integration.**

### What this means in production today

| Vector | Real-world exposure |
|---|---|
| FL_002 (Yield) | No ceiling or plausibility check exists on APY/yield claims presented to a user. A prompt claiming "10,000% APY, deposit now" is not evaluated by any real guardrail. |
| FL_003 (Trading signals) | No verification that a cited "trusted source" (Binance, Coinbase, Chainlink) is genuine. Nothing prevents social-engineered trade execution via a spoofed reference to a real exchange name. |
| FL_005 (Governance) | No real vote-weight verification exists; a real deployment has no mechanism to confirm a caller's actual on-chain voting power before acting on a governance instruction. |
| FL_008 (Slippage) | No real slippage-bounds enforcement tied to actual liquidity; a hardcoded 5% mock threshold has no counterpart in the product. |

### Why the mock passing tests didn't previously surface this

The scanner's test payloads are shaped to match exactly what the mock's hardcoded
regex/dictionaries expect (e.g. `"X% APY"`, the literal word `"binance"`). Passing
`test_hardened_security_audit.py` on these four vectors currently only proves the mock
can parse its own test inputs — it provides **no evidence about production behavior**,
and should not be read as such until real logic exists in `crypto_guard.py`.

### Exact mock-only logic today (for reference)

- **FL_002:** Extracts `r'(\d+(?:\.\d+)?)\s*%\s*(?:apy|apr|yield|return)'`, checks against
  hardcoded `SIMULATED_YIELD_BASELINES["default"]` (5.0%) × `MAX_YIELD_MULTIPLIER` (2.0),
  rejects any APY > 10.0%. Also checks destination address against `KNOWN_CONTRACTS`,
  which is an empty dict — so this branch rejects everything.
- **FL_003:** Checks for presence of any of `{"coinbase", "binance", "kraken",
  "chainlink"}` anywhere in the prompt text. Trivially bypassed by mentioning the name
  without any real verification ("I read on Reddit that Binance is going to list this
  token...").
- **FL_005:** Looks up caller in `SIMULATED_GOVERNANCE_LEDGER.get("default_caller", 0)` —
  the dict is empty, so this permanently rejects all governance votes (fails closed by
  accident, not by design).
- **FL_008:** Extracts `r'(\d+(?:\.\d+)?)\s*%'`, rejects slippage > hardcoded
  `MAX_SLIPPAGE_PCT` (5.0%). Misses non-percent phrasing entirely (e.g. "500 basis
  points", "0.05 tolerance").

---

## Fix Spec

### FL_002 — Yield/APY validation
- Replace the hardcoded 10% ceiling with dynamic comparison against real market data
  (DefiLlama or comparable yield-aggregator API) for the specific protocol/pool
  referenced.
- Flag (not necessarily hard-block) claims that exceed N standard deviations from the
  protocol's actual historical/current APY, with N tunable.
- Replace the empty `KNOWN_CONTRACTS` dict with real contract-address verification — at
  minimum a maintained allowlist or a reputation/registry API, not an empty static dict
  that currently rejects everything by omission.

### FL_003 — Trading signal / source verification
- Replace keyword string-matching with actual signed-data verification: for
  oracle-sourced signals, verify Pyth/Chainlink ECDSA signatures against the claimed
  source.
- For "I read that X said Y" style prompts, do not treat as verified regardless of
  keyword presence — these should be flagged as unverifiable, not passed as trusted.
- Explicitly distinguish "signal cryptographically verified from source" vs "prompt
  merely mentions source's name" — the current logic conflates these.

### FL_005 — Governance vote weight
- Replace static dictionary lookup with a real `web3.py` RPC call to the relevant
  contract's `getVotes(address)` / `balanceOf(address)` at current block height.
- Requires: RPC endpoint configuration, chain/contract-address mapping per supported
  governance system, and a fail-closed fallback if the RPC call itself fails or times
  out (not fail-open).

### FL_008 — Slippage validation
- Extend parsing beyond `%` regex to cover basis-points and decimal-tolerance phrasing
  ("500 basis points," "0.05 tolerance").
- Replace the static 5% ceiling with a bound computed from actual pool liquidity depth
  (via 1inch or comparable DEX aggregator API) — a 5% slippage tolerance may be
  reasonable for a deep pool and dangerous for a thin one; a flat threshold can't
  distinguish these.

### Cross-cutting requirements for all four
- External API/RPC dependencies introduce failure modes (timeout, rate limit, stale
  data) that need explicit fail-closed handling. Given this project's repeated finding
  that fail-open defaults are where real damage happens (`enforce_auth`, `/debug/info`,
  the guardrail body-scan bypass), any new integration here should default to
  blocking/flagging on integration failure, not passing through.
- None of this should be implemented by loosening the mock further — the mock's job is
  to simulate these external dependencies realistically enough to test the real logic,
  not to encode the logic itself.

---

## Final Implementation Status

- **FL_002 (Yield/APY)**: CLOSED. Hardcoded mock ceiling replaced with dynamic comparison against live DefiLlama data.
- **FL_003 (Trading Signal)**: CLOSED. Replaced string-matching with actual Pyth/Chainlink ECDSA signature requirement.
- **FL_005 (Governance)**: BLOCKED ON PREREQUISITE. The required validation architecture was built and verified via simulated test context, but cannot be enabled because the proxy framework does not currently pass authenticated session wallet identities down to the guardrails. A user-claimed voter address from a prompt is trivially spoofable and intentionally NOT parsed. Therefore, this vector is intentionally hard-blocked and marked unsupported until the Session Wallet Auth prerequisite is met.
- **FL_008 (Slippage)**: INTENTIONAL HARD-BLOCK. 100% of slippage-setting actions are hard-blocked because the required 1inch API key is unprovisioned. We explicitly rejected the fail-open "flag-and-log" approach in favor of a documented, intentional hard-block pending key configuration.

---

## Addendum: Reviewed Implementation Plan

The following implementation plan was drafted, reviewed, and revised before handoff.
It resolves five structural issues raised in review (fail-open language, unresolved
sync/async decision, `getVotes()`/`balanceOf()` conflation, unbounded API-call
multiplication, and golden-path-only testing).

### Structural Decisions & Constraints

- **Strict intent-gating:** No live API calls (DefiLlama, 1inch, RPC) are made merely
  because a financial keyword ("APY", "slippage") appears in a prompt. A lightweight
  regex intent gate confirms an actionable financial instruction (e.g. "set slippage
  to", "deposit all funds into", "execute trade") before any external network call
  fires. Educational queries bypass the expensive path entirely.
- **Synchronous execution with TTL caching:** Since `GuardianProxy` operates
  synchronously today, these checks run synchronously behind the intent gate. A TTL
  cache (5–15 min) on pool APY/liquidity baselines prevents legitimate active traffic
  from multiplying external API calls 1:1 with requests.
- **Fail-closed on integration failure:** A rate-limit exhaustion or API timeout fails
  closed *for that specific financial instruction* ("Verification Unavailable" —
  rejected). Normal non-actionable chat traffic is unaffected. No fallback path is
  permitted to fail open on an unverified address or claim.

### Proposed Changes — `guardian/audit/remediation/crypto_guard.py`

- **FL_002 (Yield/APY):** Intent gate on fund-move instructions + APY claims/external
  contract addresses. Check DefiLlama (cached) against historical market baseline;
  block if claim exceeds baseline by >2x. If protocol-name mapping is ambiguous, fall
  back to a secondary control (reputation/contract verification) — never fail open on
  an unverified address.
- **FL_003 (Trading Signals):** Intent gate on trade-execution requests + market
  data/signal claims. Explicitly distinguishes "prompt merely mentions source's name"
  (unverifiable, blocked) from "signal cryptographically verified from source" —
  requires a Pyth/Chainlink ECDSA signature block to authorize execution.
- **FL_005 (Governance):** Intent gate on vote-casting instructions. Uses `web3.py`
  with the authoritative call specified per governance system — `getVotes(address)`
  for Compound/OpenZeppelin Governor systems, with `balanceOf(address)` reserved only
  for specifically-configured token-weighted (undelegated) governance types; the two
  are not treated as interchangeable. Blocks the vote if delegated votes are 0.
- **FL_008 (Slippage):** Intent gate on explicit slippage-modification instructions
  ("500 basis points", "0.05 tolerance", "100%"). Normalizes to a percentage, queries a
  DEX aggregator (1inch) for pool liquidity depth, and computes a dynamic safe bound
  (e.g. 1% for deep pools, 5% for illiquid) rather than a flat threshold.

### Config — `guardian/config/config.yaml`

```yaml
crypto_guard:
  enabled: true
  rpc_url: "https://eth.llamarpc.com"
  defillama_api_base: "https://yields.llama.fi"
  dex_aggregator_api: "https://api.1inch.dev/swap/v6.0"
  api_timeout_ms: 2000
  cache_ttl_seconds: 300
```

### Verification Plan

**Automated:**
- `pytest tests/security/test_hardened_security_audit.py` to confirm the real guards
  (not just the mock) intercept the attacks.
- Failure-path tests in `test_crypto_guard.py`, explicitly asserting: a DefiLlama
  timeout fails closed with the correct status/reason, and simulated rate-limiting
  (429) fails closed gracefully without crashing the proxy.

**Manual:**
- Golden path: "10,000% APY" actionable prompt → blocked.
- Intent-gate check: educational question ("What is slippage tolerance in DeFi?") →
  passes immediately, no external API call or cache lookup triggered.
- Governance: vote-cast instruction from a caller with no delegated votes → blocked.
- Slippage: "100% tolerance" instruction → blocked.

### Open item for implementation

The TTL cache (5–15 min) on APY/liquidity baselines means a genuine rapid market move
could be judged against a stale cached value for up to the cache window. Whether this
false-positive-on-legitimate-volatility risk is acceptable, or whether the yield
baseline specifically needs a shorter TTL, is not yet decided and should be resolved
(with a code comment recording the reasoning) during implementation.
