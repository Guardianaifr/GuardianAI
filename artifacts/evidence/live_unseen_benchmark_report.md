# GuardianAI — Live & Unseen Empirical Benchmark Report

**Execution Timestamp:** 2026-08-20 12:22:40Z
**Total Prompts Evaluated:** 1,299

## 1. Overall Security Metrics

| Metric | Strict Mode | Balanced Mode |
|---|---|---|
| **Overall Attack Block Rate** | **88.74%** (946/1,066) | **80.02%** (853/1,066) |
| **False Positive Rate (Benign Data)** | **29.18%** (68/233) | **6.44%** (15/233) |

## 2. Dataset-by-Dataset Breakdown

| Dataset | Source | Total Prompts | Strict Block Rate | Balanced Block Rate |
|---|---|---|---|---|
| `HF_Prompt_Injections` | Hugging Face | 15 | **86.67%** (13) | 46.67% (7) |
| `HF_ChatGPT_Jailbreaks` | Hugging Face | 79 | **98.73%** (78) | 92.41% (73) |
| `HF_Jailbreak_Classification` | Hugging Face | 52 | **92.31%** (48) | 86.54% (45) |
| `GitHub_AdvBench_Harmful` | GitHub | 520 | **99.04%** (515) | 95.38% (496) |
| `GitHub_HarmBench_Official` | GitHub | 400 | **73.00%** (292) | 58.00% (232) |
| `HF_Safe_Prompts_PI` (Safe) | Hugging Face | 85 | FPR: 21.18% (18) | FPR: 3.53% (3) |
| `HF_Jailbreak_Classification_Benign` (Safe) | Hugging Face | 48 | FPR: 31.25% (15) | FPR: 10.42% (5) |
| `HF_Alpaca_Benign` (Safe) | Hugging Face | 100 | FPR: 35.00% (35) | FPR: 7.00% (7) |

## 3. Defense Layer Attribution (Strict Mode)

| Defense Layer | Prompts Blocked | Percentage of Total Blocks |
|---|---|---|
| `fast_path_regex` | 0 | 0.0% |
| `semantic_firewall` | 0 | 0.0% |
| `encoding_deobfuscator` | 945 | 99.9% |
| `system_prompt_guard` | 1 | 0.1% |

## 4. Live Performance & Latency Telemetry

| Traffic Load | Throughput | p50 Latency | p90 Latency | p95 Latency | p99 Latency |
|---|---|---|---|---|---|
| **Safe Traffic Load** | **8.29 rps** | 2187.83 ms | 4034.13 ms | **4723.14 ms** | 5513.79 ms |
| **Attack Traffic Load** | **0.1 rps** | 626.68 ms | 316255.55 ms | **2002849.78 ms** | 2420660.25 ms |
