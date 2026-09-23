# EU AI Act Compliance Report — GuardianAI

**Generated**: 2026-09-23T15:28:54.136325+00:00
**System**: GuardianAI v1.0
**Framework**: EU AI Act (Regulation 2024/1689)
**Overall Score**: 98% (compliant)

---

## Risk Classification

- **Risk Level**: LIMITED
- **Category**: general_purpose_ai_security
- **Rationale**: System provides AI security controls. Not directly classified as high-risk under Annex III, but may be embedded in high-risk deployments. Limited risk transparency obligations apply.

---

## Article Assessments

| Article | Title | Score | Status |
|---------|-------|-------|--------|
| ART_9 | Risk Management System | 100% | ✅ compliant |
| ART_10 | Data and Data Governance | 100% | ✅ compliant |
| ART_11 | Technical Documentation | 100% | ✅ compliant |
| ART_12 | Record-Keeping and Logging | 100% | ✅ compliant |
| ART_13 | Transparency and Provision of Information | 100% | ✅ compliant |
| ART_14 | Human Oversight | 100% | ✅ compliant |
| ART_15 | Accuracy, Robustness and Cybersecurity | 100% | ✅ compliant |
| ART_17 | Quality Management System | 83% | ✅ compliant |

---

## Risk Management System (Art. 9)

# Risk Management System — GuardianAI

**Framework**: EU AI Act, Article 9
**Generated**: 2026-09-23 15:28 UTC
**System**: GuardianAI v1.0

## 1. System Description

AI security control plane providing real-time guardrails, governance, and compliance for enterprise AI deployments.

**Intended Purpose**: Protect AI systems against prompt injection, data leakage, cost abuse, and adversarial attacks in production environments.

## 2. Risk Identification

### 2.1 Known Risks
- Prompt injection attacks bypassing input guardrails
- Data leakage through model outputs (PII, secrets, system prompts)
- Cost abuse via token-draining attack patterns
- Adversarial attacks degrading model safety controls
- Supply chain compromise via poisoned models or dependencies
- Agentic systems exceeding authorized scope

### 2.2 Risk Assessment Methodology
- Continuous red/blue/purple team automated probing
- Public benchmark alignment (HarmBench, AdvBench, GAIA)
- Quarterly threat model refresh (threat_model_quarterly.md)
- Community threat feed integration

## 3. Risk Mitigation Measures

| Risk | Mitigation Control | Evidence |
|------|-------------------|----------|
| Prompt injection | Input filter + AI semantic firewall | input_filter.py, ai_firewall.py |
| Data leakage | Output validator + PII redaction | output_validator.py |
| System prompt leakage | System prompt guard | system_prompt_guard.py |
| Cost abuse | Token budget + behavioral anomaly | cost_abuse.py |
| Supply chain | SBOM + model provenance | supply_chain.py |
| Agentic scope | Agent identity + scope enforcement | agentic_controls.py |
| Memory poisoning | Session memory guard | memory_guard.py |

## 4. Residual Risk

Residual risks are classified in `FALSE_NEGATIVE_TAXONOMY.md`:
- Low-signal prompt shaping (minimal residual risk)
- Tool-chain indirection (mitigated by tool policy engine)
- Retrieval contamination drift (mitigated by RAG guard)
- Multimodal latent instruction encoding (baseline scanning active)

## 5. Monitoring and Review

- SLO targets defined and validated: `security_slo_targets.json`
- Performance/chaos validation: `perf_chaos_report.json`
- Benchmark regression gate: `public_benchmark_targets.json`
- Quarterly threat model refresh cycle active

---

## Transparency Report (Art. 13)

# Transparency Report — GuardianAI

**Framework**: EU AI Act, Article 13
**Generated**: 2026-09-23 15:28 UTC

## 1. System Identity

- **Name**: GuardianAI
- **Version**: 1.0
- **Provider**: Not specified
- **Type**: AI Security Control Plane (Proxy + Guardrails + Governance)

## 2. Intended Purpose

Protect AI systems against prompt injection, data leakage, cost abuse, and adversarial attacks in production environments.

## 3. Capabilities

- Real-time prompt injection detection and blocking
- AI semantic firewall with multi-turn context analysis
- Output validation, PII detection, and data leak prevention
- System prompt leakage protection (OWASP LLM07)
- Cost abuse detection with behavioral anomaly analysis
- Multi-tenant isolation with per-tenant security profiles
- Agentic security controls (identity, scope, kill-switch)
- RAG and multimodal input scanning
- Red/blue/purple team automated security orchestration

## 4. Known Limitations

- Detection relies on pattern matching and semantic similarity; novel zero-day attacks may bypass initial detection
- AI firewall accuracy depends on jailbreak vector corpus quality and coverage
- Multimodal scanning provides baseline coverage; binary-level OCR/transcription requires additional adapters
- System prompt leakage detection uses n-gram overlap; heavily paraphrased leaks may score below threshold

## 5. Performance Metrics

| Metric | Value | Source |
|--------|-------|--------|
| HarmBench block rate | 72.8% strict / 57.8% balanced | public_benchmark_report.json |
| AdvBench block rate | 99.0% strict / 95.6% balanced | public_benchmark_report.json |
| Baseline p95 latency | 587.83 ms | perf_chaos_report.json |
| Attack block rate | 100% | perf_chaos_report.json |

*Note: Prior benchmark figures (GAIA, composite 93.6%, etc.) were retracted.*

## 6. Human Oversight

- Global agent kill-switch available (`agent_kill_switch.json`)
- Per-session revocation via Blue Team adaptive controls
- Enforce/audit mode toggle for all security controls
- False-positive review queue for analyst override
- Per-tenant sensitivity tuning (strict/balanced/lenient)

---

## Conformity Checklist

| ID | Requirement | Status | Evidence |
|----|-------------|--------|----------|
| CF-01 | Risk management system established and documented (Art. 9) | ✅ implemented | threat_model_quarterly.md, FALSE_NEGATIVE_TAXONOMY.md |
| CF-02 | Data governance practices documented (Art. 10) | ⚠️ partial | data_governance_audit.md |
| CF-03 | Technical documentation maintained (Art. 11) | ✅ implemented | END_TO_END_PROJECT_DOCUMENTATION.md, API.md, RELEASE_NOTES.md |
| CF-04 | Automatic event logging with tamper resistance (Art. 12) | ✅ implemented | evidence_export.py, compliance_bundle.json |
| CF-05 | Transparency and instructions for use (Art. 13) | ✅ implemented | README.md, DEPLOYMENT.md, OPERATIONS.md |
| CF-06 | Human oversight mechanisms (Art. 14) | ✅ implemented | agentic_controls.py, feedback_loop.py, policy_governance.py |
| CF-07 | Accuracy levels declared and measured (Art. 15) | ✅ implemented | public_benchmark_report.json, perf_chaos_report.json |
| CF-08 | Robustness against adversarial attacks (Art. 15) | ✅ implemented | ai_firewall.py, input_filter.py, hardening_checks.py |
| CF-09 | Cybersecurity measures against unauthorized manipulation (Ar | ✅ implemented | rate_limiter.py, supply_chain.py, output_watermark.py |
| CF-10 | Quality management system (Art. 17) | ⚠️ partial | pytest.ini, CONTRIBUTING.md, .github/ |
| CF-11 | Post-market monitoring system | ✅ implemented | siem.py, brain/orchestrator.py |
| CF-12 | Incident reporting procedures | ✅ implemented | incident_drill_report.md, SECURITY.md |

---

## ISO/IEC 42001 QMS Mapping

| ISO Clause | EU AI Act | Guardian Control | Status |
|-----------|-----------|------------------|--------|
| 4 - Context of the organization | Art. 9, 17 | config.yaml — System configuration and scope defin | ✅ mapped |
| 5 - Leadership | Art. 17 | policy_governance.py — Governance gate with approv | ✅ mapped |
| 6 - Planning | Art. 9 | ROADMAP.md — Development planning; security_slo_ta | ✅ mapped |
| 7 - Support | Art. 11, 13 | Documentation suite (README, API, DEPLOYMENT, OPER | ✅ mapped |
| 8 - Operation | Art. 9, 14, 15 | interceptor.py — Runtime security operations | ✅ mapped |
| 9 - Performance evaluation | Art. 15 | Public benchmarks + performance chaos validation | ✅ mapped |
| 10 - Improvement | Art. 9, 17 | brain/orchestrator.py — Auto-patch + continuous im | ✅ mapped |