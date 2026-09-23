"""
EU AI Act Compliance Assessment Engine

Provides automated compliance assessment, documentation generation, and
conformity checking aligned to the EU Artificial Intelligence Act (Regulation
2024/1689) — specifically Articles 9-17 and Annex III for high-risk systems.

Enforceable: August 2, 2026 for high-risk AI systems (Annex III).

This module maps GuardianAI's existing security controls to EU AI Act
requirements and identifies gaps requiring remediation.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ArticleAssessment:
    """Assessment result for a single EU AI Act article."""
    article_id: str
    article_title: str
    status: str          # "compliant" | "partial" | "non_compliant" | "not_applicable"
    score: float         # 0.0–1.0
    findings: List[str]
    evidence_refs: List[str]
    recommendations: List[str]


@dataclass
class RiskClassification:
    """AI system risk classification per Annex III."""
    risk_level: str        # "unacceptable" | "high" | "limited" | "minimal"
    annex_iii_category: str
    rationale: str
    applicable_articles: List[str]


@dataclass
class ComplianceReport:
    """Full EU AI Act compliance report."""
    generated_at_utc: str
    framework: str
    framework_version: str
    system_name: str
    system_version: str
    risk_classification: Dict[str, Any]
    article_assessments: List[Dict[str, Any]]
    overall_score: float
    overall_status: str    # "compliant" | "conditional" | "non_compliant"
    summary: str
    rms_document: str      # Risk Management System document (Art. 9)
    transparency_report: str  # Transparency report (Art. 13)
    conformity_checklist: List[Dict[str, Any]]
    qms_mapping: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Risk Classification (Annex III)
# ---------------------------------------------------------------------------

# Annex III high-risk categories with keywords for auto-detection
ANNEX_III_CATEGORIES = {
    "1_biometric": {
        "title": "Biometric identification and categorisation of natural persons",
        "keywords": ["biometric", "facial recognition", "fingerprint", "iris", "voice identification"],
    },
    "2_critical_infrastructure": {
        "title": "Management and operation of critical infrastructure",
        "keywords": ["critical infrastructure", "energy", "water supply", "transport", "digital infrastructure"],
    },
    "3_education": {
        "title": "Education and vocational training",
        "keywords": ["education", "student", "school", "grading", "admission", "learning assessment"],
    },
    "4_employment": {
        "title": "Employment, workers management and access to self-employment",
        "keywords": ["hiring", "recruitment", "employee", "HR", "resume screening", "performance evaluation"],
    },
    "5_essential_services": {
        "title": "Access to and enjoyment of essential private and public services",
        "keywords": ["credit scoring", "insurance", "healthcare", "social benefits", "emergency services"],
    },
    "6_law_enforcement": {
        "title": "Law enforcement",
        "keywords": ["law enforcement", "police", "criminal", "surveillance", "profiling"],
    },
    "7_migration": {
        "title": "Migration, asylum and border control management",
        "keywords": ["migration", "asylum", "border", "visa", "immigration"],
    },
    "8_justice": {
        "title": "Administration of justice and democratic processes",
        "keywords": ["judiciary", "court", "legal decision", "sentencing", "election"],
    },
}


# ---------------------------------------------------------------------------
# Article Definitions and Control Mappings
# ---------------------------------------------------------------------------

ARTICLE_DEFINITIONS = {
    "art_9": {
        "title": "Risk Management System",
        "description": "Establish and maintain a continuous, iterative risk management process throughout the AI system lifecycle.",
        "requirements": [
            "Documented risk identification and assessment process",
            "Risk mitigation measures for identified risks",
            "Residual risk acceptance criteria",
            "Continuous monitoring and updating of risk assessments",
            "Testing procedures to ensure risk management effectiveness",
        ],
        "guardian_controls": [
            "threat_model_quarterly.md — Quarterly threat model refresh",
            "perf_chaos_report.json — Performance and chaos validation",
            "FALSE_NEGATIVE_TAXONOMY.md — Residual risk classification",
            "brain/orchestrator.py — Continuous red/blue/purple team loop",
            "security_slo_targets.json — SLO acceptance criteria",
        ],
    },
    "art_10": {
        "title": "Data and Data Governance",
        "description": "Training, validation, and testing datasets must be relevant, representative, and free of errors.",
        "requirements": [
            "Data governance practices documentation",
            "Dataset quality and relevance assessment",
            "Bias detection and mitigation procedures",
            "Data provenance and lineage tracking",
            "Privacy-preserving data handling",
        ],
        "guardian_controls": [
            "data_governance_audit.md — Data governance documentation",
            "differential_privacy.py — DP controls for analytics",
            "supply_chain.py — Model provenance tracking",
            "output_validator.py — PII detection and redaction",
        ],
    },
    "art_11": {
        "title": "Technical Documentation",
        "description": "Draw up technical documentation before placing on market, kept up-to-date.",
        "requirements": [
            "System description and intended purpose",
            "Design specifications and development methodology",
            "Monitoring, functioning, and control description",
            "Risk management system documentation",
            "Changes and updates log",
        ],
        "guardian_controls": [
            "END_TO_END_PROJECT_DOCUMENTATION.md — Full system documentation",
            "FEATURE_BENCHMARK_ANALYSIS.md — Feature inventory and benchmarks",
            "API.md — API documentation",
            "RELEASE_NOTES.md — Changes and updates log",
        ],
    },
    "art_12": {
        "title": "Record-Keeping and Logging",
        "description": "Automatic recording of events (logs) throughout the AI system lifecycle.",
        "requirements": [
            "Automatic event logging capability",
            "Tamper-resistant log storage",
            "Log retention and accessibility policies",
            "Traceability of decisions and actions",
            "Incident logging and reporting",
        ],
        "guardian_controls": [
            "evidence_export.py — Tamper-evident evidence signing",
            "interceptor.py — Automatic event reporting to backend",
            "tenant_isolation.py — Per-tenant evidence directories",
            "siem.py — SIEM integration for log forwarding",
            "incident_drill_report.md — Incident response documentation",
        ],
    },
    "art_13": {
        "title": "Transparency and Provision of Information",
        "description": "High-risk AI systems shall be designed to ensure transparency and enable deployers to interpret outputs.",
        "requirements": [
            "Clear instructions for use provided to deployers",
            "System capabilities and limitations documented",
            "Intended purpose and foreseeable misuse documented",
            "Performance metrics and known limitations",
            "Human oversight instructions",
        ],
        "guardian_controls": [
            "README.md — System overview and instructions",
            "DEPLOYMENT.md — Deployment guide",
            "TROUBLESHOOTING.md — Known issues and limitations",
            "public_benchmark_report.md — Published performance metrics",
            "OPERATIONS.md — Operational guide",
        ],
    },
    "art_14": {
        "title": "Human Oversight",
        "description": "High-risk AI systems shall be designed to allow effective human oversight.",
        "requirements": [
            "Human-in-the-loop intervention capability",
            "System halt/interrupt capability (kill switch)",
            "Override and correction mechanisms",
            "Alert mechanisms for anomalous behavior",
            "Feedback and review workflows",
        ],
        "guardian_controls": [
            "agentic_controls.py — Agent kill-switch (global pause)",
            "feedback_loop.py — False-positive review workflow",
            "tenant_sensitivity.py — Per-tenant sensitivity tuning",
            "policy_governance.py — Governance gate with enforce/audit mode",
            "brain/orchestrator.py — Session revoke enforcement",
        ],
    },
    "art_15": {
        "title": "Accuracy, Robustness and Cybersecurity",
        "description": "High-risk AI systems shall achieve appropriate accuracy, robustness, and cybersecurity resilience.",
        "requirements": [
            "Accuracy levels declared and measurable",
            "Resilience against errors and inconsistencies",
            "Resilience against adversarial attacks",
            "Redundancy and fail-safe mechanisms",
            "Cybersecurity measures against unauthorized manipulation",
        ],
        "guardian_controls": [
            "perf_chaos_report.json — Accuracy and performance benchmarks",
            "public_benchmark_report.json — HarmBench/AdvBench/GAIA scores",
            "ai_firewall.py — Adversarial attack detection",
            "input_filter.py — Prompt injection protection",
            "rate_limiter.py — DoS protection",
            "hardening_checks.py — Poisoning/tamper detection",
        ],
    },
    "art_17": {
        "title": "Quality Management System",
        "description": "Providers shall put in place a quality management system ensuring compliance.",
        "requirements": [
            "Compliance strategy and procedures documented",
            "Design, development, and testing procedures",
            "Examination, test, and validation procedures",
            "Change management and version control",
            "Post-market monitoring system",
            "Incident reporting procedures",
            "Communication with regulatory authorities",
        ],
        "guardian_controls": [
            "CONTRIBUTING.md — Development procedures",
            "pytest.ini + tests/ — Testing framework (51+ test files)",
            "RELEASE_NOTES.md — Change management",
            ".github/ — CI/CD workflows",
            "SECURITY.md — Security communication procedures",
            "compliance_bundle.json — Compliance evidence bundling",
        ],
    },
}


# ---------------------------------------------------------------------------
# Core Assessment Engine
# ---------------------------------------------------------------------------

class EUAIActAssessment:
    """EU AI Act compliance assessment engine.

    Evaluates GuardianAI's existing controls against EU AI Act requirements
    and generates compliance documentation.

    Config keys:
        - enabled (bool): Enable the compliance module. Default: True.
        - system_name (str): Name of the AI system. Default: "GuardianAI".
        - system_version (str): System version. Default: "1.0".
        - system_description (str): System purpose description.
        - intended_purpose (str): Intended use of the system.
        - deployer_organization (str): Name of the deploying organization.
    """

    FRAMEWORK = "EU AI Act (Regulation 2024/1689)"
    FRAMEWORK_VERSION = "2024"

    def __init__(self, config: Optional[Dict[str, Any]] = None, root_dir: Optional[Path] = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.system_name = str(cfg.get("system_name", "GuardianAI"))
        self.system_version = str(cfg.get("system_version", "1.0"))
        self.system_description = str(cfg.get(
            "system_description",
            "AI security control plane providing real-time guardrails, "
            "governance, and compliance for enterprise AI deployments."
        ))
        self.intended_purpose = str(cfg.get(
            "intended_purpose",
            "Protect AI systems against prompt injection, data leakage, "
            "cost abuse, and adversarial attacks in production environments."
        ))
        self.deployer_org = str(cfg.get("deployer_organization", ""))
        self.root_dir = root_dir or Path(__file__).resolve().parent.parent

    # ------------------------------------------------------------------
    # Risk Classification
    # ------------------------------------------------------------------

    def classify_risk(self, system_description: Optional[str] = None) -> RiskClassification:
        """Classify AI system risk level per Annex III.

        Args:
            system_description: Description to analyze. Defaults to config value.

        Returns:
            RiskClassification with risk level and applicable articles.
        """
        desc = (system_description or self.system_description).lower()

        # Check against Annex III categories
        for cat_id, cat_info in ANNEX_III_CATEGORIES.items():
            for keyword in cat_info["keywords"]:
                if keyword.lower() in desc:
                    return RiskClassification(
                        risk_level="high",
                        annex_iii_category=cat_info["title"],
                        rationale=f"System description matches Annex III category keyword: '{keyword}'",
                        applicable_articles=list(ARTICLE_DEFINITIONS.keys()),
                    )

        # Default classification for security infrastructure
        return RiskClassification(
            risk_level="limited",
            annex_iii_category="general_purpose_ai_security",
            rationale="System provides AI security controls. Not directly classified "
                      "as high-risk under Annex III, but may be embedded in high-risk "
                      "deployments. Limited risk transparency obligations apply.",
            applicable_articles=["art_13", "art_15"],
        )

    # ------------------------------------------------------------------
    # Per-Article Assessment
    # ------------------------------------------------------------------

    def assess_article(self, article_id: str) -> ArticleAssessment:
        """Assess compliance for a single EU AI Act article.

        Args:
            article_id: Article identifier (e.g., "art_9").

        Returns:
            ArticleAssessment with status, score, and findings.
        """
        defn = ARTICLE_DEFINITIONS.get(article_id)
        if not defn:
            return ArticleAssessment(
                article_id=article_id,
                article_title="Unknown",
                status="not_applicable",
                score=0.0,
                findings=["Article not defined in assessment framework"],
                evidence_refs=[],
                recommendations=[],
            )

        controls = defn.get("guardian_controls", [])
        requirements = defn.get("requirements", [])

        # Check which evidence files actually exist
        existing_evidence = []
        missing_evidence = []
        for control in controls:
            ref_file = control.split(" — ")[0].strip()
            found = self._evidence_exists(ref_file)
            if found:
                existing_evidence.append(control)
            else:
                missing_evidence.append(control)

        # Score based on control coverage
        if not controls:
            coverage = 0.0
        else:
            coverage = len(existing_evidence) / len(controls)

        # Map coverage to status
        if coverage >= 0.8:
            status = "compliant"
        elif coverage >= 0.5:
            status = "partial"
        else:
            status = "non_compliant"

        # Build findings
        findings = []
        if existing_evidence:
            findings.append(f"{len(existing_evidence)}/{len(controls)} controls verified with evidence")
        if missing_evidence:
            findings.append(f"{len(missing_evidence)} controls missing evidence: "
                           + ", ".join(m.split(' — ')[0] for m in missing_evidence))

        # Build recommendations
        recommendations = []
        if status != "compliant":
            for req in requirements:
                if not any(req.lower()[:20] in c.lower() for c in existing_evidence):
                    recommendations.append(f"Address: {req}")

        return ArticleAssessment(
            article_id=article_id,
            article_title=defn["title"],
            status=status,
            score=round(coverage, 2),
            findings=findings,
            evidence_refs=[c.split(" — ")[0] for c in existing_evidence],
            recommendations=recommendations[:5],  # Cap at 5 most important
        )

    # ------------------------------------------------------------------
    # Full Compliance Assessment
    # ------------------------------------------------------------------

    def assess_compliance(self) -> ComplianceReport:
        """Run full compliance assessment against all articles.

        Returns:
            ComplianceReport with per-article assessments and overall score.
        """
        risk = self.classify_risk()
        assessments = []
        total_score = 0.0
        article_count = 0

        for article_id in ARTICLE_DEFINITIONS:
            assessment = self.assess_article(article_id)
            assessments.append(asdict(assessment))
            total_score += assessment.score
            article_count += 1

        overall_score = round(total_score / max(article_count, 1), 2)

        if overall_score >= 0.8:
            overall_status = "compliant"
        elif overall_score >= 0.5:
            overall_status = "conditional"
        else:
            overall_status = "non_compliant"

        non_compliant = [a for a in assessments if a["status"] == "non_compliant"]
        partial = [a for a in assessments if a["status"] == "partial"]

        summary_parts = [
            f"EU AI Act compliance assessment for {self.system_name} v{self.system_version}.",
            f"Risk classification: {risk.risk_level} ({risk.annex_iii_category}).",
            f"Overall score: {overall_score:.0%} ({overall_status}).",
            f"Articles assessed: {article_count}.",
        ]
        if non_compliant:
            summary_parts.append(
                f"Non-compliant: {', '.join(a['article_id'] for a in non_compliant)}."
            )
        if partial:
            summary_parts.append(
                f"Partial compliance: {', '.join(a['article_id'] for a in partial)}."
            )

        return ComplianceReport(
            generated_at_utc=datetime.now(timezone.utc).isoformat(),
            framework=self.FRAMEWORK,
            framework_version=self.FRAMEWORK_VERSION,
            system_name=self.system_name,
            system_version=self.system_version,
            risk_classification=asdict(risk),
            article_assessments=assessments,
            overall_score=overall_score,
            overall_status=overall_status,
            summary=" ".join(summary_parts),
            rms_document=self.generate_rms_document(),
            transparency_report=self.generate_transparency_report(),
            conformity_checklist=self.generate_conformity_checklist(),
            qms_mapping=self.generate_qms_mapping(),
        )

    # ------------------------------------------------------------------
    # Document Generators
    # ------------------------------------------------------------------

    def generate_rms_document(self) -> str:
        """Generate Risk Management System documentation (Art. 9).

        Returns:
            Markdown-formatted RMS document.
        """
        lines = [
            f"# Risk Management System — {self.system_name}",
            f"",
            f"**Framework**: EU AI Act, Article 9",
            f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**System**: {self.system_name} v{self.system_version}",
            f"",
            f"## 1. System Description",
            f"",
            f"{self.system_description}",
            f"",
            f"**Intended Purpose**: {self.intended_purpose}",
            f"",
            f"## 2. Risk Identification",
            f"",
            f"### 2.1 Known Risks",
            f"- Prompt injection attacks bypassing input guardrails",
            f"- Data leakage through model outputs (PII, secrets, system prompts)",
            f"- Cost abuse via token-draining attack patterns",
            f"- Adversarial attacks degrading model safety controls",
            f"- Supply chain compromise via poisoned models or dependencies",
            f"- Agentic systems exceeding authorized scope",
            f"",
            f"### 2.2 Risk Assessment Methodology",
            f"- Continuous red/blue/purple team automated probing",
            f"- Public benchmark alignment (HarmBench, AdvBench, GAIA)",
            f"- Quarterly threat model refresh (threat_model_quarterly.md)",
            f"- Community threat feed integration",
            f"",
            f"## 3. Risk Mitigation Measures",
            f"",
            f"| Risk | Mitigation Control | Evidence |",
            f"|------|-------------------|----------|",
            f"| Prompt injection | Input filter + AI semantic firewall | input_filter.py, ai_firewall.py |",
            f"| Data leakage | Output validator + PII redaction | output_validator.py |",
            f"| System prompt leakage | System prompt guard | system_prompt_guard.py |",
            f"| Cost abuse | Token budget + behavioral anomaly | cost_abuse.py |",
            f"| Supply chain | SBOM + model provenance | supply_chain.py |",
            f"| Agentic scope | Agent identity + scope enforcement | agentic_controls.py |",
            f"| Memory poisoning | Session memory guard | memory_guard.py |",
            f"",
            f"## 4. Residual Risk",
            f"",
            f"Residual risks are classified in `FALSE_NEGATIVE_TAXONOMY.md`:",
            f"- Low-signal prompt shaping (minimal residual risk)",
            f"- Tool-chain indirection (mitigated by tool policy engine)",
            f"- Retrieval contamination drift (mitigated by RAG guard)",
            f"- Multimodal latent instruction encoding (baseline scanning active)",
            f"",
            f"## 5. Monitoring and Review",
            f"",
            f"- SLO targets defined and validated: `security_slo_targets.json`",
            f"- Performance/chaos validation: `perf_chaos_report.json`",
            f"- Benchmark regression gate: `public_benchmark_targets.json`",
            f"- Quarterly threat model refresh cycle active",
        ]
        return "\n".join(lines)

    def generate_transparency_report(self) -> str:
        """Generate Transparency report (Art. 13).

        Returns:
            Markdown-formatted transparency report.
        """
        lines = [
            f"# Transparency Report — {self.system_name}",
            f"",
            f"**Framework**: EU AI Act, Article 13",
            f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"",
            f"## 1. System Identity",
            f"",
            f"- **Name**: {self.system_name}",
            f"- **Version**: {self.system_version}",
            f"- **Provider**: {self.deployer_org or 'Not specified'}",
            f"- **Type**: AI Security Control Plane (Proxy + Guardrails + Governance)",
            f"",
            f"## 2. Intended Purpose",
            f"",
            f"{self.intended_purpose}",
            f"",
            f"## 3. Capabilities",
            f"",
            f"- Real-time prompt injection detection and blocking",
            f"- AI semantic firewall with multi-turn context analysis",
            f"- Output validation, PII detection, and data leak prevention",
            f"- System prompt leakage protection (OWASP LLM07)",
            f"- Cost abuse detection with behavioral anomaly analysis",
            f"- Multi-tenant isolation with per-tenant security profiles",
            f"- Agentic security controls (identity, scope, kill-switch)",
            f"- RAG and multimodal input scanning",
            f"- Red/blue/purple team automated security orchestration",
            f"",
            f"## 4. Known Limitations",
            f"",
            f"- Detection relies on pattern matching and semantic similarity; novel zero-day attacks may bypass initial detection",
            f"- AI firewall accuracy depends on jailbreak vector corpus quality and coverage",
            f"- Multimodal scanning provides baseline coverage; binary-level OCR/transcription requires additional adapters",
            f"- System prompt leakage detection uses n-gram overlap; heavily paraphrased leaks may score below threshold",
            f"",
            f"## 5. Performance Metrics",
            f"",
            f"| Metric | Value | Source |",
            f"|--------|-------|--------|",
            f"| HarmBench block rate | 72.8% strict / 57.8% balanced | public_benchmark_report.json |",
            f"| AdvBench block rate | 99.0% strict / 95.6% balanced | public_benchmark_report.json |",
            f"| Baseline p95 latency | 587.83 ms | perf_chaos_report.json |",
            f"| Attack block rate | 100% | perf_chaos_report.json |",
            f"",
            f"*Note: Prior benchmark figures (GAIA, composite 93.6%, etc.) were retracted.*",
            f"",
            f"## 6. Human Oversight",
            f"",
            f"- Global agent kill-switch available (`agent_kill_switch.json`)",
            f"- Per-session revocation via Blue Team adaptive controls",
            f"- Enforce/audit mode toggle for all security controls",
            f"- False-positive review queue for analyst override",
            f"- Per-tenant sensitivity tuning (strict/balanced/lenient)",
        ]
        return "\n".join(lines)

    def generate_conformity_checklist(self) -> List[Dict[str, Any]]:
        """Generate conformity self-assessment checklist.

        Returns:
            List of checklist items with status and evidence.
        """
        checklist = [
            {
                "id": "CF-01",
                "requirement": "Risk management system established and documented (Art. 9)",
                "status": "implemented",
                "evidence": ["threat_model_quarterly.md", "FALSE_NEGATIVE_TAXONOMY.md"],
                "notes": "Continuous risk assessment via red/blue/purple team automation",
            },
            {
                "id": "CF-02",
                "requirement": "Data governance practices documented (Art. 10)",
                "status": "partial",
                "evidence": ["data_governance_audit.md"],
                "notes": "Basic data governance documentation exists; needs expansion for training data specifics",
            },
            {
                "id": "CF-03",
                "requirement": "Technical documentation maintained (Art. 11)",
                "status": "implemented",
                "evidence": ["END_TO_END_PROJECT_DOCUMENTATION.md", "API.md", "RELEASE_NOTES.md"],
                "notes": "Comprehensive documentation covering all 32+ features",
            },
            {
                "id": "CF-04",
                "requirement": "Automatic event logging with tamper resistance (Art. 12)",
                "status": "implemented",
                "evidence": ["evidence_export.py", "compliance_bundle.json"],
                "notes": "HMAC-signed evidence bundles with cloud key provider support",
            },
            {
                "id": "CF-05",
                "requirement": "Transparency and instructions for use (Art. 13)",
                "status": "implemented",
                "evidence": ["README.md", "DEPLOYMENT.md", "OPERATIONS.md"],
                "notes": "Deployment, operations, and troubleshooting documentation provided",
            },
            {
                "id": "CF-06",
                "requirement": "Human oversight mechanisms (Art. 14)",
                "status": "implemented",
                "evidence": ["agentic_controls.py", "feedback_loop.py", "policy_governance.py"],
                "notes": "Kill-switch, session revocation, enforce/audit toggle, FP review queue",
            },
            {
                "id": "CF-07",
                "requirement": "Accuracy levels declared and measured (Art. 15)",
                "status": "implemented",
                "evidence": ["public_benchmark_report.json", "perf_chaos_report.json"],
                "notes": "Published benchmark scores: HarmBench 72.8%, AdvBench 99.0% (GAIA retracted)",
            },
            {
                "id": "CF-08",
                "requirement": "Robustness against adversarial attacks (Art. 15)",
                "status": "implemented",
                "evidence": ["ai_firewall.py", "input_filter.py", "hardening_checks.py"],
                "notes": "Multi-layer input protection + chaos validation harness",
            },
            {
                "id": "CF-09",
                "requirement": "Cybersecurity measures against unauthorized manipulation (Art. 15)",
                "status": "implemented",
                "evidence": ["rate_limiter.py", "supply_chain.py", "output_watermark.py"],
                "notes": "Rate limiting, supply chain verification, output watermarking",
            },
            {
                "id": "CF-10",
                "requirement": "Quality management system (Art. 17)",
                "status": "partial",
                "evidence": ["pytest.ini", "CONTRIBUTING.md", ".github/"],
                "notes": "CI/CD and testing framework in place; formal QMS procedures need documentation",
            },
            {
                "id": "CF-11",
                "requirement": "Post-market monitoring system",
                "status": "implemented",
                "evidence": ["siem.py", "brain/orchestrator.py"],
                "notes": "SIEM integration + continuous red/blue/purple team monitoring",
            },
            {
                "id": "CF-12",
                "requirement": "Incident reporting procedures",
                "status": "implemented",
                "evidence": ["incident_drill_report.md", "SECURITY.md"],
                "notes": "Incident drills documented; security contact procedures in SECURITY.md",
            },
        ]
        return checklist

    def generate_qms_mapping(self) -> List[Dict[str, Any]]:
        """Generate QMS mapping aligned to ISO/IEC 42001.

        Returns:
            Mapping of ISO 42001 clauses to GuardianAI controls.
        """
        mapping = [
            {
                "iso_clause": "4 - Context of the organization",
                "eu_ai_act_article": "Art. 9, 17",
                "guardian_control": "config.yaml — System configuration and scope definition",
                "status": "mapped",
            },
            {
                "iso_clause": "5 - Leadership",
                "eu_ai_act_article": "Art. 17",
                "guardian_control": "policy_governance.py — Governance gate with approval workflow",
                "status": "mapped",
            },
            {
                "iso_clause": "6 - Planning",
                "eu_ai_act_article": "Art. 9",
                "guardian_control": "ROADMAP.md — Development planning; security_slo_targets.json",
                "status": "mapped",
            },
            {
                "iso_clause": "7 - Support",
                "eu_ai_act_article": "Art. 11, 13",
                "guardian_control": "Documentation suite (README, API, DEPLOYMENT, OPERATIONS)",
                "status": "mapped",
            },
            {
                "iso_clause": "8 - Operation",
                "eu_ai_act_article": "Art. 9, 14, 15",
                "guardian_control": "interceptor.py — Runtime security operations",
                "status": "mapped",
            },
            {
                "iso_clause": "9 - Performance evaluation",
                "eu_ai_act_article": "Art. 15",
                "guardian_control": "Public benchmarks + performance chaos validation",
                "status": "mapped",
            },
            {
                "iso_clause": "10 - Improvement",
                "eu_ai_act_article": "Art. 9, 17",
                "guardian_control": "brain/orchestrator.py — Auto-patch + continuous improvement loop",
                "status": "mapped",
            },
        ]
        return mapping

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _evidence_exists(self, ref_file: str) -> bool:
        """Check if an evidence file/module exists in the project."""
        search_paths = [
            self.root_dir / ref_file,
            self.root_dir / "artifacts" / "evidence" / ref_file,
            self.root_dir / "artifacts" / "performance" / ref_file,
            self.root_dir / "guardian" / "security" / ref_file,
            self.root_dir / "guardian" / "guardrails" / ref_file,
            self.root_dir / "guardian" / "runtime" / ref_file,
            self.root_dir / "guardian" / ref_file,
            self.root_dir / "backend" / ref_file,
        ]
        return any(p.exists() for p in search_paths)
