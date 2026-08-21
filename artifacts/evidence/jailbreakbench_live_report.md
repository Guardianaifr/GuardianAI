# GuardianAI — Official JailbreakBench Live Benchmark Report

**Source:** [JailbreakBench Artifacts Repository](https://github.com/JailbreakBench/artifacts)
**Execution Timestamp:** 2026-08-20 16:37:18Z
**Total Adversarial Prompts Evaluated:** 251
**Total Benign Prompts Evaluated:** 100

## 1. Overall JailbreakBench Performance

| Metric | Strict Mode | Balanced Mode |
|---|---|---|
| **Overall JBB Attack Block Rate** | **98.80%** (248/251) | **89.64%** (225/251) |
| **False Positive Rate (Benign JBB)** | **89.00%** (89/100) | **78.00%** (78/100) |

## 2. Attack Suite Breakdown

| Attack Technique / Target | Total Prompts | Strict Block Rate | Balanced Block Rate |
|---|---|---|---|
| `JBB_PAIR_Attack_GPT4` | 64 | **96.88%** (62) | 84.38% (54) |
| `JBB_PAIR_Attack_GPT35` | 87 | **98.85%** (86) | 95.40% (83) |
| `JBB_Prompt_Random_Search_GPT4` | 100 | **100.00%** (100) | 88.00% (88) |

## 3. Category Breakdown (OWASP / JBB Taxonomy)

| Harm Category | Total Prompts | Strict Block Rate | Balanced Block Rate |
|---|---|---|---|
| **Disinformation** | 23 | **95.7%** (22) | 87.0% (20) |
| **Economic harm** | 25 | **92.0%** (23) | 72.0% (18) |
| **Expert advice** | 20 | **100.0%** (20) | 55.0% (11) |
| **Fraud/Deception** | 26 | **100.0%** (26) | 96.2% (25) |
| **Government decision-making** | 29 | **100.0%** (29) | 89.7% (26) |
| **Harassment/Discrimination** | 30 | **100.0%** (30) | 96.7% (29) |
| **Malware/Hacking** | 25 | **100.0%** (25) | 100.0% (25) |
| **Physical harm** | 23 | **100.0%** (23) | 100.0% (23) |
| **Privacy** | 25 | **100.0%** (25) | 96.0% (24) |
| **Sexual/Adult content** | 25 | **100.0%** (25) | 96.0% (24) |
