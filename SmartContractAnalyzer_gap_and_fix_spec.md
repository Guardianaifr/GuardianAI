# Smart Contract Static Analyzer — Gap Documentation & Fix Spec

**Severity: CRITICAL (29 classes)**
**Remaining scope: 29 of 52 declared rules (23 FALSE-SIGNAL + 6 SHALLOW)**
**Scope: `guardian/audit/smart_contract_analyzer.py` / `guardian/audit/slither_detectors.py`**
**Date raised: 2026-07-19 — Date of fix + verification: 2026-07-23 (for first 18) / 2026-07-25 (5 additional genuine)**
**Fix commit: `f9bc2a4695b4bc8a4cec4fa3f00582a2fd23b66b`**

---

## Resolution Summary (added 2026-07-23)

The 18 highest-severity classes documented below as FALSE-SIGNAL/SHALLOW have been
rebuilt on a hybrid Slither AST/CFG + custom-detector engine and are now verified
**18/18 correctly passing** their vulnerable/safe/evasion test triples, plus additional
sanity-check contracts constructed independently of the original diagnostic fixtures.

- **Engine:** `slither-analyzer==0.11.5` (pinned in `requirements.txt`), used via its
  Python API for structural analysis (control flow, state-mutation ordering, actual
  modifier resolution), with custom AST-walking logic layered on top for
  GuardianAI-specific semantic checks Slither doesn't natively know about (e.g. that a
  renamed `mint`-like function is still a minting function).
- **Verification:** 92 fixture contracts (the original 3-per-class plus additional
  named-alternate and sanity-check variants) now run as parametrized pytest cases in
  `tests/audit/test_smart_contract_analyzer.py` — promoted from a standalone script so
  this runs as part of the normal test suite going forward, not a manual step someone
  has to remember. Current state: 92/92 passing, full suite regression-checked at 1065
  passed / 2 skipped, 0 failed.
- **Process note:** the medium/high-complexity rules (SC-101, SC-102, SC-111, SC-114,
  SC-116, SC-122) were implemented in a single combined round rather than the
  originally-agreed one-sub-batch-at-a-time checkpoint process. This was caught,
  disclosed, and retroactively verified via reconstructed pre/post isolation testing and
  file-modification-time/diff evidence (git tracking was added only at the end of this
  work) — no cross-contamination between rules was found, but the deviation itself is
  noted here as a process lesson for any future batch of this size.
- **Business/compliance exposure (Section "Business/compliance exposure" below):** the
  original concern — that Feature 32's SOC-2/ISO 27001 compliance-mapping claims
  couldn't be trusted while 17/18 rules were false-signal — is resolved for these 18
  classes. It remains an open concern for the ~34 untested rules below.

The original diagnostic findings are preserved below for record — they describe the
state *before* this fix, not the current state.

## Gap Documentation

### Finding

The smart contract static analyzer's detection logic is entirely regex/pattern-based, with
**zero AST parsing or structural analysis** of Solidity syntax, control flow, or state
changes. Of the 18 highest-severity classes tested with matched vulnerable/safe/evasion
contract triples, **17 of 18 (94%) are FALSE-SIGNAL**: they flag the properly-mitigated,
secure version of the code identically to the vulnerable version. Only 1 class (SC-119 /
whitepaper SC-010, Unprotected `initialize()`) correctly distinguishes vulnerable- **Pending Migration Scope (29 Rules):**
  - **FALSE-SIGNAL (23):** `SC-002`, `SC-010`, `SC-011`, `SC-061`, `SC-100`, `SC-103`, `SC-104`, `SC-106`, `SC-107`, `SC-110`, `SC-115`, `SC-117`, `SC-118`, `SC-121`, `SC-123`, `SC-124`, `SC-080`, `VY-001`, `VY-003`, `VY-004`, `SC-130`, `SC-133`, `SC-135`
  - **SHALLOW (6):** `SC-021`, `SC-032`, `SC-081`, `VY-005`, `SC-132`, `SC-134`
  - **GENUINE (23):** 18 previously fixed + 5 confirmed genuine in the pending set (`SC-040`, `SC-070`, `SC-120`, `VY-002`, `SC-131`). These 5 require no fix work, only test verification.

This is a more severe failure mode than a normal detection gap. A tool that cannot tell
vulnerable code from the code that correctly fixes that exact vulnerability is not
providing weak security signal — for those 17 classes, it is providing **no security
signal**, while appearing to. Worse, false-positiving on secure code trains users to
distrust or override findings, which degrades the value of any *genuine* finding the
tool does produce.

### Test methodology

For each class: a minimal unambiguous **vulnerable** contract, a **safe** contract using
the same risky primitive correctly (checks-effects-interactions, real access control,
nonce/sequence checks, supply caps, etc. — tests false positives), and an **evasion**
contract achieving the same vulnerability through trivially different syntax (renamed
function, added whitespace, different library call — tests false negatives). All three
were run through the real analyzer with command-paired raw output.

### Results — 18 classes tested

| Whitepaper ID | Vulnerability Class | Code ID | Diagnosis | Flaw |
|---|---|---|---|---|
| SC-001 | Reentrancy | SC-001 | FALSE-SIGNAL | Flags checks-effects-interactions; evaded by `gas:` kwarg |
| SC-002 | Integer Overflow | SC-020 | FALSE-SIGNAL | Flags correct SafeMath usage on old pragmas |
| SC-003 | Access Control Flaws | SC-031 | FALSE-SIGNAL | Flags `requiresAuth`; evaded by renaming function |
| SC-004 | Front-Running / Sandwich | SC-114 | FALSE-SIGNAL | Flags valid slippage checks; evaded by rename |
| SC-005 | tx.origin Authentication | SC-030 | FALSE-SIGNAL | Flags valid contract-denial pattern; evaded by operand order |
| SC-006 | Delegatecall Misuse | SC-041 | FALSE-SIGNAL | Flags trusted hardcoded target; evaded by a space before `(` |
| SC-007 | selfdestruct / Kill-switch | SC-042 | FALSE-SIGNAL | Flags timelocked usage; evaded via delegatecall to destroy logic |
| SC-008 | Flash Loan Attack Surface | SC-060 | FALSE-SIGNAL | Flags safe TWAP usage; evaded by renaming call |
| SC-009 | Timestamp Dependence | SC-050 | FALSE-SIGNAL | Flags non-critical/UI uses; evaded by variable assignment |
| SC-010 | Unprotected `initialize()` | SC-119 | SHALLOW | Correctly suppresses on safe keyword — only class that distinguishes vuln/safe — but evaded by renaming to `init()` |
| SC-011 | Unverified Proxy Patterns | SC-105 | FALSE-SIGNAL | Flags standard, correctly-verified OZ proxies (cannot check on-chain verification state) |
| SC-012 | No Timelock on Role Changes | SC-101 | FALSE-SIGNAL | Flags `onlyGovDAO`-protected grants; evaded by a code comment |
| SC-013 | Uncapped Mint Authority | SC-102 | FALSE-SIGNAL | Flags a real supply-cap check; evaded by renaming function |
| SC-014 | Oracle Centralization | SC-122 | FALSE-SIGNAL | Flags a real median-of-3-oracles setup; evaded by renaming |
| SC-015 | Bridge/Signature Replay | SC-111 | FALSE-SIGNAL | Flags real nonce/sequence checks; evaded by using `ECDSA.recover` instead of raw `ecrecover` |
| SC-016 | Read-Only Reentrancy | SC-113 | FALSE-SIGNAL | Flags `nonReentrant`-protected view functions; evaded by renaming |
| SC-017 | Storage Collision (Proxy) | SC-112 | FALSE-SIGNAL | Flags valid Diamond Storage layout; evaded by renaming the inherited Proxy |
| SC-018 | Governance Attack | SC-116 | FALSE-SIGNAL | Flags `onlyOwner`-protected voting; evaded by renaming function |

### Rule count vs. whitepaper claim

The whitepaper's "35+ vulnerability classes" claim is **numerically accurate** — 52
distinct rules exist in the `VULN_RULES` constant, confirmed by direct enumeration, not
estimation. However, given the 17/18 false-signal rate on the tested subset, the
substantive claim behind that number — that these are working detection rules — is not
supported by the evidence. 52 regex patterns with this failure rate is closer to an
expanded false-positive generator than a vulnerability detector.

### Why this happened

Every rule triggers on the literal presence or absence of a keyword/token pattern (e.g.
"contains `.call{value:`" or "contains `mint` without containing `onlyOwner`"), with no
understanding of Solidity's actual syntax tree, control flow, or semantic equivalence
between different valid ways of expressing the same safeguard (e.g. `onlyOwner` vs
`requiresAuth` vs `onlyGovDAO` are functionally similar but only one specific spelling is
checked per rule).

### Business/compliance exposure

Feature 32 in the current whitepaper states this analyzer provides "compliance mappings
to SOC-2 and ISO 27001" and "remediation guidance" per finding. Given the false-signal
rate found, any compliance documentation generated from this tool's output should not be
represented as validated security analysis until this is fixed. This is a distinct risk
from the technical gap itself and should be treated as its own action item.

---

## Fix Spec

### Why regex-tuning is not a viable fix

Tightening any individual pattern to stop flagging its safe case will, by the same
mechanism already observed across every class tested, open a new evasion gap elsewhere
(renaming a function, adding whitespace, swapping a semantically-equivalent library call
all defeated detection here). This is the identical shape of problem PI_002/PI_010 has as
a documented known limitation — closing one payload shape doesn't close the vulnerability
class. Regex-based detection has a structural ceiling for this problem; it cannot be
patched past that ceiling.

### Recommended approach

Replace pattern-matching with real Solidity AST analysis:

- **Parse, don't grep:** Use a real Solidity parser (e.g. `solidity-parser-antlr`,
  `solc`'s own AST output via `--ast-compact-json`, or an existing analyzer engine like
  Slither as a library) to build an actual syntax tree per contract, rather than treating
  source as a string to pattern-match.
- **Reason about structure, not spelling:** For example, reentrancy detection should
  verify whether a state-changing assignment occurs before or after an external call in
  control-flow order — not whether the literal substring `.call{value:` appears anywhere
  in the file. Access-control detection should resolve whatever modifier is actually
  attached to a function and check whether *some* access-restricting modifier exists,
  not whether one specific spelling (`onlyOwner`) is present.
- **Prioritize by real severity, not rule count:** Start with the 8 originally-tested
  CRITICAL classes (reentrancy, access control, delegatecall, flash loan, unprotected
  init, uncapped mint, signature replay, governance) since they carry the highest
  exploit impact; the remaining ~34 rules should be re-evaluated with the same
  vuln/safe/evasion methodology before any are trusted, not assumed fixed by association.
- **Re-run this exact test methodology after any fix**, per rule, before marking it
  closed — the vuln/safe/evasion triple is now the standard verification bar for this
  module, same as it became for FL_002/003/005/008.

### Scope note

This is a substantially larger engineering effort than any single fix in this audit so
far — closer in scope to "replace a subsystem" than "patch a function." It should be
scoped and staffed as its own project, not folded into incremental prompt-driven fixes.

### Immediate interim step (not a technical fix, but should happen regardless of timeline)

Until real detection exists, any customer-facing or compliance-facing output from this
analyzer should carry an explicit accuracy caveat, and Feature 32 / Section 5's
whitepaper claims (SOC-2/ISO 27001 compliance mapping, "35+ vulnerability classes"
framed as a differentiator) should be corrected or caveated the same way Section 6 was
corrected earlier — a specific, falsifiable capability claim should not be represented
as validated when it has been directly tested and found not to hold for 17 of 18 sampled
classes.

---

## Status

**18 of 52 rules: FIXED, verified (92/92 fixture pass rate), committed
(`f9bc2a4695b4bc8a4cec4fa3f00582a2fd23b66b`), and covered by permanent pytest
regression tests.**

**34 of 52 rules: still untested.** Do not assume safe or broken without the same
empirical methodology used here. This is the remaining open scope of this finding.
