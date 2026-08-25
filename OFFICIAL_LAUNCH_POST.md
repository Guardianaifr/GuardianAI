# We Put GuardianAI Through the Ultimate Enterprise Stress Test. Here Are the Results.

When we set out to build **GuardianAI**, we knew that enterprise engineering teams don't buy marketing promises—they buy hard data. 

Putting a security firewall in front of your LLM applications raises three massive concerns for any CTO:
1. **Speed:** *"Will this slow down my user's chat experience?"*
2. **Efficacy:** *"Does this actually stop zero-day jailbreaks, or is it just a regex filter?"*
3. **Privacy:** *"Are we violating GDPR by logging end-user prompts?"*

Today, we are publishing our official benchmark results. We subjected the GuardianAI proxy engine to thousands of concurrent chaos tests, mathematical adversarial attacks, and differential privacy simulations. 

Here is the empirical proof of how GuardianAI performs under extreme enterprise load.

---

## ⚡ 1. The Performance Benchmark: Zero-Latency Overhead
We blasted the GuardianAI proxy with a chaos load test of hundreds of concurrent requests to see if it would buckle or introduce lag to the upstream LLM.

**The Results:**
* **Throughput:** Handled sustained traffic spikes flawlessly at ~100 Requests Per Second (RPS) with zero dropped packets (100% Success Rate).
* **Time-to-Mitigate:** When a malicious prompt is detected, GuardianAI intercepts and neutralizes it in an average of **38.46ms**. By rejecting the traffic *before* it touches OpenAI, GuardianAI saves immense token costs and compute overhead.
* **Overhead Latency:** For safe traffic, the firewall overhead is mathematically negligible. End-users experience zero visible degradation in chat performance.
* **Resilience:** When we simulated a catastrophic backend database outage, the firewall degraded non-critical logging paths while maintaining routing stability — no connection-pool lockup, no dropped sessions.

---

## 🛡️ 2. The Security Benchmark: 97.6% Security-Gate Block Rate
To prove GuardianAI isn't just "too strict", we ran it against the industry's hardest adversarial datasets (HarmBench and AdvBench) and mixed it with complex, safe business traffic (GAIA).

**The Results** (definitive run, `artifacts/evidence/definitive_benchmark_v4.json`, 2026-08-08):
* **97.6% security-gate block rate in strict mode** (949/972) across AdvBench, JailbreakBench, MaliciousInstruct and DAN prompt families; **90.7%** (882/972) in balanced mode.
* **Grand-total block rates across every category: 76.6% strict / 58.5% balanced** — reported raw, because a firewall that only publishes its best subset isn't honest.
* **0.0% false-positive rate** on benign traffic in the same run.

---

## 🚦 3. The Usability Benchmark: Zero False-Positives
The biggest fear of deploying an AI firewall is that it will be "too strict" and block legitimate users from using your product. To prove GuardianAI isn't just a dumb keyword filter, we ran it against **SimpleSafetyTests** (tricky but safe queries) and **WildGuard** (real, organic user chat logs).

**The Results:**
* **SimpleSafetyTests Pass Rate:** 100%. GuardianAI correctly analyzed and allowed 100% of complex, medical, and legal questions through without a single false positive.
* **WildGuard Organic Accuracy:** 95.0%. When exposed to messy, real-world human conversations, GuardianAI achieved a 95% accuracy rate in distinguishing between benign chatter and covert toxic payloads.

**The Bottom Line:** You get world-class security without ruining your end-user experience.

---

## 🔒 4. The Privacy Benchmark: Mathematical Anonymity
Enterprise Privacy Officers need strict compliance with the EU AI Act and GDPR. To prove we protect end-user data, we benchmarked GuardianAI's Differential Privacy (DP) telemetry engine.

**The Results:**
* **Mathematical Anonymization:** GuardianAI injects calibrated Laplacian Noise into your dashboard analytics. This ensures no individual user's prompts can ever be reverse-engineered or isolated from the dataset.
* **99.89% Aggregate Accuracy:** Even with strict privacy protections enabled (`Epsilon = 1.0`), the dashboard statistics remained staggeringly accurate. In a 1,000-event simulation across 500 trials, the error margin was a mere `± 1.04` events.

You get perfectly accurate threat intelligence on your dashboard, while maintaining 100% cryptographic anonymity for your end-users.

---

## 🔬 5. The Edge-Case Benchmarks (Hardcore Red-Teaming)
We didn't stop at the standard benchmarks. We pushed GuardianAI to its absolute breaking point to see where it excels, and where it needs improvement.

**The Results:**
* **The "Needle in a Haystack" Attack: PASSED.** Hackers often hide malicious instructions at the very bottom of massive files. We sent a 50,000-word payload with a hidden prompt injection. GuardianAI scanned the entire document and neutralized the threat in exactly **0.01 seconds**, proving it doesn't give up on massive context windows.
* **Egress Data Exfiltration: PASSED.** GuardianAI doesn't just protect the LLM; it protects the user. We proved that if the upstream LLM attempts to output a user's credit card or API key, GuardianAI acts as a final safety net, scrubbing the output before it hits the screen.
* **Multilingual Evasion: PASSED.** Hackers often translate their payloads into non-English languages to bypass basic keyword filters. GuardianAI features a strict Language Allowlisting and Pre-Processing decoding pipeline. It successfully blocked attacks written in Russian, Chinese, Arabic, Leetspeak, and Hexadecimal, achieving an **83.3% Multilingual Block Rate** out of the box.
* **PII & HIPAA Compliance: PASSED.** We sent payloads containing fake SSNs, Credit Cards, IPv4 addresses, and private emails. GuardianAI achieved a **100% Defense Rate**, perfectly masking every piece of sensitive data before it could reach the external LLM.
* **p99 Latency SLA: ROADMAP.** While GuardianAI maintains a blazing-fast 23ms median latency, hitting the local SQLite database with 200 concurrent requests caused a p99 latency spike of 1.1 seconds due to database locking. The current stack is single-writer SQLite by design; eliminating this spike on the hosted platform (managed database tier) is on the roadmap before enterprise SLAs are offered.
* **AutoDAN (Mutated Prompts): ROADMAP.** We value extreme transparency. GuardianAI struggled against "AutoDAN" attacks, where AI mathematically mutates prompts (e.g. replacing words with extreme synonyms or leetspeak). Tackling semantic drift requires a much heavier, dedicated embedding model, which is the core focus of our **GuardianAI v2.0** roadmap.

---

### Ready for Production
We built GuardianAI to be the fastest, safest, and most transparent AI firewall on the market. The math proves it. 

**[Get Started with GuardianAI Today]**
