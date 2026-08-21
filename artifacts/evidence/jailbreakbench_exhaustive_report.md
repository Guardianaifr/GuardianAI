# GuardianAI — Exhaustive JailbreakBench Benchmark Report

**Repository Source:** [JailbreakBench Official Artifacts](https://github.com/JailbreakBench/artifacts)
**Execution Timestamp:** 2026-08-20 17:24:35Z
**Total Attack Prompts Evaluated:** 1,637
**Total Benign Prompts Evaluated:** 100

## 1. Overall Benchmark Summary

| Metric | Strict Mode (0.45) | Balanced Mode (0.55) |
|---|---|---|
| **Overall JBB Attack Block Rate** | **99.69%** (1,632/1,637) | **92.36%** (1,512/1,637) |
| **False Positive Rate (Benign JBB)** | **89.00%** (89/100) | **79.00%** (79/100) |

## 2. Breakdown by Attack Algorithm

| Attack Algorithm | Total Prompts | Strict Mode Block Rate | Balanced Mode Block Rate |
|---|---|---|---|
| **DSN** | 200 | **100.00%** (200) | 90.50% (181) |
| **GCG_Transfer** | 200 | **100.00%** (200) | 92.00% (184) |
| **GCG_Whitebox** | 200 | **100.00%** (200) | 90.00% (180) |
| **JBC_Manual** | 400 | **100.00%** (400) | 100.00% (400) |
| **PAIR** | 237 | **97.89%** (232) | 89.45% (212) |
| **Random_Search** | 400 | **100.00%** (400) | 88.75% (355) |

## 3. Breakdown by Target Model

| Target Model | Total Prompts | Strict Mode Block Rate | Balanced Mode Block Rate |
|---|---|---|---|
| **GPT-3.5** | 387 | **99.74%** (386) | 94.06% (364) |
| **GPT-4** | 364 | **99.45%** (362) | 92.03% (335) |
| **Llama-2-7B** | 404 | **100.00%** (404) | 91.34% (369) |
| **Vicuna-13B** | 482 | **99.59%** (480) | 92.12% (444) |

## 4. Breakdown Across All 10 JBB Harm Categories

| Harm Category | Total Prompts | Strict Mode Block Rate | Balanced Mode Block Rate |
|---|---|---|---|
| **Disinformation** | 160 | **99.38%** (159) | 93.75% (150) |
| **Economic harm** | 163 | **98.16%** (160) | 80.98% (132) |
| **Expert advice** | 158 | **99.37%** (157) | 53.80% (85) |
| **Fraud/Deception** | 164 | **100.00%** (164) | 99.39% (163) |
| **Government decision-making** | 168 | **100.00%** (168) | 96.43% (162) |
| **Harassment/Discrimination** | 171 | **100.00%** (171) | 98.83% (169) |
| **Malware/Hacking** | 165 | **100.00%** (165) | 100.00% (165) |
| **Physical harm** | 161 | **100.00%** (161) | 100.00% (161) |
| **Privacy** | 163 | **100.00%** (163) | 99.39% (162) |
| **Sexual/Adult content** | 164 | **100.00%** (164) | 99.39% (163) |

## 5. Defense Layer Attribution (Strict Mode)

| Defense Layer | Prompts Blocked | Percentage |
|---|---|---|
| `fast_path_regex` | 439 | 26.9% |
| `semantic_firewall` | 1,193 | 73.1% |
