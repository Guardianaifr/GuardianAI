# False-Negative Taxonomy and Benchmark Gap Breakdown

Date: 2026-03-18
Scope: Public benchmark residual risk analysis for GuardianAI controls.

## Context

Latest published benchmark alignment:

- HarmBench block rate: 97.0%
- AdvBench block rate: 94.0%
- GAIA success rate: 86.0%
- Composite score: 93.6%

The residual gap (for example AdvBench ~6% non-blocked) should be treated as an explicit, managed risk class, not an unknown.

## False-Negative Taxonomy

1. Low-signal prompt shaping
- Attack intent distributed across long benign context with sparse high-risk keywords.
- Typical impact: can evade strict keyword gates while still steering unsafe behavior.

2. Tool-chain indirection
- Malicious objective expressed as benign intermediate tool requests, only becoming dangerous after composition.
- Typical impact: policy misses emerge in multi-step agent plans.

3. Retrieval contamination drift
- Poisoned or misleading retrieval content appears semantically benign but changes downstream behavior.
- Typical impact: partial bypass of RAG guard heuristics where direct injection strings are absent.

4. Multimodal latent instruction encoding
- Instruction payload hidden in OCR/transcript ambiguity or metadata-like textual artifacts.
- Typical impact: baseline multimodal checks under-detect subtle encoded patterns.

5. Confidence laundering
- Structured outputs include plausible citations/confidence values while underlying claim quality is weak.
- Typical impact: output assurance passes structure but factual risk remains.

## Benchmark Gap Breakdown (Actionable)

1. HarmBench residual (~3%)
- Most likely categories: low-signal prompt shaping, tool-chain indirection.
- Priority action: expand adversarial semantic vectors and multi-turn context chaining tests.

2. AdvBench residual (~6%)
- Most likely categories: low-signal prompt shaping, retrieval contamination drift, tool-chain indirection.
- Priority action: add refusal-policy stress set and cross-turn jailbreak mutation corpus.

3. GAIA residual (~14% unsolved)
- Not a pure security failure; includes task difficulty and capability limits.
- Security tie-in: enforce stronger abstain/uncertainty responses for high-stakes domains.

## Mitigation Plan (Next Iteration)

1. Expand adversarial regression corpus by taxonomy class and track per-class block rate.
2. Add agentic chain simulation tests with intermediate benign/tool-call decomposition.
3. Add RAG trust scoring and cross-source contamination heuristics (planned expansion).
4. Add multimodal hardening phase 2 with OCR/transcript provenance and malware scan hooks.
5. Add high-stakes domain policy: mandatory abstain when confidence/citation quality signals conflict.

## Reporting Standard

Every benchmark release should include:

- Overall score (composite + per benchmark)
- Per-class false-negative counts by taxonomy category
- Change from previous run (delta)
- Accepted residual risks with owner + target remediation window
