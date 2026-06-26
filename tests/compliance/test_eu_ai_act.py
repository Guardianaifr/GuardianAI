"""
Tests for EU AI Act Compliance Assessment Engine.

Covers:
  - Risk classification (Annex III categories)
  - Per-article assessment
  - Full compliance report generation
  - RMS document generation (Art. 9)
  - Transparency report generation (Art. 13)
  - Conformity checklist generation
  - ISO 42001 QMS mapping
  - Edge cases (disabled, custom config, unknown articles)
"""
import pytest
import sys
import os
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "guardian"))

from compliance.eu_ai_act import (
    EUAIActAssessment,
    RiskClassification,
    ArticleAssessment,
    ComplianceReport,
    ARTICLE_DEFINITIONS,
    ANNEX_III_CATEGORIES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def engine():
    config = {
        "enabled": True,
        "system_name": "GuardianAI-Test",
        "system_version": "2.0",
        "deployer_organization": "TestCorp",
    }
    return EUAIActAssessment(config=config, root_dir=ROOT_DIR)


@pytest.fixture
def disabled_engine():
    return EUAIActAssessment(config={"enabled": False}, root_dir=ROOT_DIR)


# ---------------------------------------------------------------------------
# Test: Risk Classification (Annex III)
# ---------------------------------------------------------------------------

class TestRiskClassification:
    def test_default_classification_is_limited(self, engine):
        """GuardianAI itself is classified as limited risk (security infra)."""
        risk = engine.classify_risk()
        assert risk.risk_level == "limited"
        assert len(risk.applicable_articles) >= 2

    def test_biometric_system_classified_as_high(self, engine):
        risk = engine.classify_risk("Facial recognition system for biometric identification")
        assert risk.risk_level == "high"
        assert "art_9" in risk.applicable_articles
        assert "biometric" in risk.rationale.lower()

    def test_employment_system_classified_as_high(self, engine):
        risk = engine.classify_risk("AI system for resume screening and hiring decisions")
        assert risk.risk_level == "high"

    def test_healthcare_system_classified_as_high(self, engine):
        risk = engine.classify_risk("AI system for healthcare insurance claim processing")
        assert risk.risk_level == "high"

    def test_education_system_classified_as_high(self, engine):
        risk = engine.classify_risk("AI system for student grading and admission decisions")
        assert risk.risk_level == "high"

    def test_law_enforcement_classified_as_high(self, engine):
        risk = engine.classify_risk("AI surveillance system for law enforcement profiling")
        assert risk.risk_level == "high"

    def test_generic_chatbot_classified_as_limited(self, engine):
        risk = engine.classify_risk("General purpose customer support chatbot")
        assert risk.risk_level == "limited"

    def test_high_risk_includes_all_articles(self, engine):
        risk = engine.classify_risk("Biometric facial recognition system")
        assert len(risk.applicable_articles) == len(ARTICLE_DEFINITIONS)

    def test_classification_returns_dataclass(self, engine):
        risk = engine.classify_risk()
        assert isinstance(risk, RiskClassification)
        assert hasattr(risk, "risk_level")
        assert hasattr(risk, "annex_iii_category")
        assert hasattr(risk, "rationale")
        assert hasattr(risk, "applicable_articles")


# ---------------------------------------------------------------------------
# Test: Per-Article Assessment
# ---------------------------------------------------------------------------

class TestArticleAssessment:
    def test_all_articles_assessable(self, engine):
        """Every defined article should produce an assessment."""
        for article_id in ARTICLE_DEFINITIONS:
            assessment = engine.assess_article(article_id)
            assert isinstance(assessment, ArticleAssessment)
            assert assessment.article_id == article_id
            assert assessment.status in ("compliant", "partial", "non_compliant", "not_applicable")
            assert 0.0 <= assessment.score <= 1.0

    def test_article_15_should_be_compliant(self, engine):
        """Art. 15 (Accuracy/Robustness/Cybersecurity) should score high."""
        assessment = engine.assess_article("art_15")
        assert assessment.score >= 0.5
        assert assessment.status in ("compliant", "partial")
        assert len(assessment.evidence_refs) > 0

    def test_article_12_logging(self, engine):
        """Art. 12 (Record-Keeping) should score well given our evidence system."""
        assessment = engine.assess_article("art_12")
        assert assessment.score >= 0.4
        assert len(assessment.evidence_refs) > 0

    def test_article_14_human_oversight(self, engine):
        """Art. 14 (Human Oversight) has kill-switch + feedback loop."""
        assessment = engine.assess_article("art_14")
        assert assessment.score >= 0.4

    def test_unknown_article_returns_not_applicable(self, engine):
        assessment = engine.assess_article("art_99")
        assert assessment.status == "not_applicable"
        assert assessment.score == 0.0

    def test_assessment_has_all_fields(self, engine):
        assessment = engine.assess_article("art_9")
        assert hasattr(assessment, "article_id")
        assert hasattr(assessment, "article_title")
        assert hasattr(assessment, "status")
        assert hasattr(assessment, "score")
        assert hasattr(assessment, "findings")
        assert hasattr(assessment, "evidence_refs")
        assert hasattr(assessment, "recommendations")
        assert isinstance(assessment.findings, list)
        assert isinstance(assessment.evidence_refs, list)
        assert isinstance(assessment.recommendations, list)


# ---------------------------------------------------------------------------
# Test: Full Compliance Assessment
# ---------------------------------------------------------------------------

class TestFullAssessment:
    def test_full_report_generated(self, engine):
        report = engine.assess_compliance()
        assert isinstance(report, ComplianceReport)
        assert report.system_name == "GuardianAI-Test"
        assert report.system_version == "2.0"
        assert report.framework == "EU AI Act (Regulation 2024/1689)"
        assert report.framework_version == "2024"

    def test_report_has_all_articles(self, engine):
        report = engine.assess_compliance()
        article_ids = {a["article_id"] for a in report.article_assessments}
        for article_id in ARTICLE_DEFINITIONS:
            assert article_id in article_ids

    def test_overall_score_is_average(self, engine):
        report = engine.assess_compliance()
        assert 0.0 <= report.overall_score <= 1.0
        assert report.overall_status in ("compliant", "conditional", "non_compliant")

    def test_report_has_generated_timestamp(self, engine):
        report = engine.assess_compliance()
        assert report.generated_at_utc is not None
        assert len(report.generated_at_utc) > 10

    def test_report_has_risk_classification(self, engine):
        report = engine.assess_compliance()
        assert "risk_level" in report.risk_classification
        assert "annex_iii_category" in report.risk_classification

    def test_report_summary_not_empty(self, engine):
        report = engine.assess_compliance()
        assert len(report.summary) > 50


# ---------------------------------------------------------------------------
# Test: Document Generation
# ---------------------------------------------------------------------------

class TestDocumentGeneration:
    def test_rms_document_generated(self, engine):
        doc = engine.generate_rms_document()
        assert "Risk Management System" in doc
        assert "GuardianAI-Test" in doc
        assert "Article 9" in doc
        assert "Risk Identification" in doc
        assert "Risk Mitigation" in doc
        assert "Residual Risk" in doc
        assert "Monitoring and Review" in doc

    def test_transparency_report_generated(self, engine):
        doc = engine.generate_transparency_report()
        assert "Transparency Report" in doc
        assert "GuardianAI-Test" in doc
        assert "Article 13" in doc
        assert "Capabilities" in doc
        assert "Known Limitations" in doc
        assert "Performance Metrics" in doc
        assert "Human Oversight" in doc
        assert "TestCorp" in doc  # deployer_org

    def test_rms_document_is_markdown(self, engine):
        doc = engine.generate_rms_document()
        assert doc.startswith("# ")
        assert "##" in doc
        assert "|" in doc  # Has tables

    def test_transparency_report_is_markdown(self, engine):
        doc = engine.generate_transparency_report()
        assert doc.startswith("# ")
        assert "##" in doc


# ---------------------------------------------------------------------------
# Test: Conformity Checklist
# ---------------------------------------------------------------------------

class TestConformityChecklist:
    def test_checklist_not_empty(self, engine):
        checklist = engine.generate_conformity_checklist()
        assert isinstance(checklist, list)
        assert len(checklist) >= 10

    def test_checklist_items_have_required_fields(self, engine):
        checklist = engine.generate_conformity_checklist()
        for item in checklist:
            assert "id" in item
            assert "requirement" in item
            assert "status" in item
            assert "evidence" in item
            assert "notes" in item
            assert item["status"] in ("implemented", "partial", "not_implemented")

    def test_checklist_has_implemented_items(self, engine):
        checklist = engine.generate_conformity_checklist()
        implemented = [c for c in checklist if c["status"] == "implemented"]
        assert len(implemented) >= 5  # We should have at least 5 implemented

    def test_checklist_ids_unique(self, engine):
        checklist = engine.generate_conformity_checklist()
        ids = [item["id"] for item in checklist]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Test: QMS Mapping (ISO 42001)
# ---------------------------------------------------------------------------

class TestQMSMapping:
    def test_qms_mapping_not_empty(self, engine):
        mapping = engine.generate_qms_mapping()
        assert isinstance(mapping, list)
        assert len(mapping) >= 7  # ISO 42001 has 7 main clauses (4-10)

    def test_qms_mapping_items_have_required_fields(self, engine):
        mapping = engine.generate_qms_mapping()
        for item in mapping:
            assert "iso_clause" in item
            assert "eu_ai_act_article" in item
            assert "guardian_control" in item
            assert "status" in item

    def test_all_clauses_mapped(self, engine):
        mapping = engine.generate_qms_mapping()
        mapped = [m for m in mapping if m["status"] == "mapped"]
        assert len(mapped) == len(mapping)  # All should be mapped


# ---------------------------------------------------------------------------
# Test: Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_default_config(self):
        engine = EUAIActAssessment()
        assert engine.system_name == "GuardianAI"
        assert engine.enabled is True

    def test_none_config(self):
        engine = EUAIActAssessment(config=None)
        assert engine.enabled is True

    def test_custom_system_description(self):
        engine = EUAIActAssessment(config={
            "system_description": "AI system for biometric facial recognition",
        }, root_dir=ROOT_DIR)
        risk = engine.classify_risk()
        assert risk.risk_level == "high"

    def test_annex_iii_categories_defined(self):
        assert len(ANNEX_III_CATEGORIES) >= 8

    def test_article_definitions_complete(self):
        required_articles = ["art_9", "art_10", "art_11", "art_12", "art_13", "art_14", "art_15", "art_17"]
        for art in required_articles:
            assert art in ARTICLE_DEFINITIONS
            assert "title" in ARTICLE_DEFINITIONS[art]
            assert "requirements" in ARTICLE_DEFINITIONS[art]
            assert "guardian_controls" in ARTICLE_DEFINITIONS[art]

    def test_report_serializable_to_json(self, engine):
        """Full report should be JSON-serializable for CI integration."""
        from dataclasses import asdict
        report = engine.assess_compliance()
        report_dict = asdict(report)
        json_str = json.dumps(report_dict, default=str)
        parsed = json.loads(json_str)
        assert parsed["system_name"] == "GuardianAI-Test"
        assert "article_assessments" in parsed
        assert "conformity_checklist" in parsed
