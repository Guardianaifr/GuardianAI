"""
Tests for Dependency Pinning CI Gate.

Covers requirement parsing, pinning detection, SBOM generation,
and the check_pinning function with various scenarios.
"""
import pytest
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))

from check_dep_pinning import (
    parse_requirements_file,
    find_requirements_files,
    check_pinning,
    generate_sbom,
    Dependency,
    PinningReport,
    SBOMReport,
)


@pytest.fixture
def req_dir(tmp_path):
    return tmp_path


# ---------------------------------------------------------------------------
# Test: Requirement Parsing
# ---------------------------------------------------------------------------

class TestRequirementParsing:
    def test_pinned_dependency(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("flask==2.3.0\n")
        deps = parse_requirements_file(str(f))
        assert len(deps) == 1
        assert deps[0].name == "flask"
        assert deps[0].version_spec == "==2.3.0"
        assert deps[0].is_pinned is True

    def test_unpinned_dependency(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("flask>=2.0\n")
        deps = parse_requirements_file(str(f))
        assert deps[0].is_pinned is False

    def test_no_version(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("flask\n")
        deps = parse_requirements_file(str(f))
        assert deps[0].version_spec == ""
        assert deps[0].is_pinned is False

    def test_multiple_deps(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("flask==2.3.0\nrequests>=2.28\nnumpy\n")
        deps = parse_requirements_file(str(f))
        assert len(deps) == 3
        assert deps[0].is_pinned is True
        assert deps[1].is_pinned is False
        assert deps[2].is_pinned is False

    def test_comments_ignored(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("# This is a comment\nflask==2.3.0\n# Another comment\n")
        deps = parse_requirements_file(str(f))
        assert len(deps) == 1

    def test_empty_lines_ignored(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("\nflask==2.3.0\n\n\n")
        deps = parse_requirements_file(str(f))
        assert len(deps) == 1

    def test_includes_ignored(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("-r base.txt\nflask==2.3.0\n")
        deps = parse_requirements_file(str(f))
        assert len(deps) == 1

    def test_extras_parsed(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("requests[security]==2.31.0\n")
        deps = parse_requirements_file(str(f))
        assert deps[0].name == "requests"
        assert deps[0].is_pinned is True

    def test_environment_markers(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("pywin32==306 ; sys_platform == 'win32'\n")
        deps = parse_requirements_file(str(f))
        assert deps[0].name == "pywin32"
        assert deps[0].is_pinned is True

    def test_nonexistent_file(self):
        deps = parse_requirements_file("/nonexistent/requirements.txt")
        assert deps == []

    def test_line_numbers_tracked(self, req_dir):
        f = req_dir / "requirements.txt"
        f.write_text("# header\nflask==2.3.0\n\nrequests==2.31.0\n")
        deps = parse_requirements_file(str(f))
        assert deps[0].line_number == 2
        assert deps[1].line_number == 4


# ---------------------------------------------------------------------------
# Test: File Discovery
# ---------------------------------------------------------------------------

class TestFileDiscovery:
    def test_finds_requirements_txt(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==1.0\n")
        files = find_requirements_files(str(req_dir))
        assert len(files) >= 1

    def test_finds_dev_requirements(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==1.0\n")
        (req_dir / "requirements-dev.txt").write_text("pytest==7.0\n")
        files = find_requirements_files(str(req_dir))
        assert len(files) >= 2

    def test_empty_project(self, req_dir):
        files = find_requirements_files(str(req_dir))
        assert files == []


# ---------------------------------------------------------------------------
# Test: Pinning Check
# ---------------------------------------------------------------------------

class TestPinningCheck:
    def test_all_pinned_passes(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==2.3.0\nrequests==2.31.0\n")
        report = check_pinning(str(req_dir))
        assert report.passed is True
        assert report.pin_rate == 1.0
        assert report.unpinned_deps == 0

    def test_unpinned_fails(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==2.3.0\nrequests>=2.28\n")
        report = check_pinning(str(req_dir), strict=True)
        assert report.passed is False
        assert report.unpinned_deps == 1
        assert report.unpinned_list[0].name == "requests"

    def test_non_strict_accepts_version_ranges(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask>=2.3.0\nrequests~=2.28\n")
        report = check_pinning(str(req_dir), strict=False)
        assert report.passed is True  # Non-strict only fails on no-version

    def test_no_deps_passes(self, req_dir):
        report = check_pinning(str(req_dir))
        assert report.passed is True
        assert report.total_deps == 0

    def test_report_has_scan_time(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==1.0\n")
        report = check_pinning(str(req_dir))
        assert report.scan_time  # Non-empty


# ---------------------------------------------------------------------------
# Test: SBOM Generation
# ---------------------------------------------------------------------------

class TestSBOMGeneration:
    def test_sbom_structure(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==2.3.0\nrequests==2.31.0\n")
        sbom = generate_sbom(str(req_dir), "TestProject", "0.1.0")
        assert sbom.bom_format == "CycloneDX"
        assert sbom.spec_version == "1.5"
        assert len(sbom.components) == 2
        assert sbom.metadata["component"]["name"] == "TestProject"

    def test_sbom_purl_format(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==2.3.0\n")
        sbom = generate_sbom(str(req_dir))
        assert sbom.components[0]["purl"] == "pkg:pypi/flask@2.3.0"

    def test_sbom_json_serializable(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==2.3.0\n")
        sbom = generate_sbom(str(req_dir))
        from dataclasses import asdict
        json_str = json.dumps(asdict(sbom))
        assert len(json_str) > 100
        parsed = json.loads(json_str)
        assert parsed["bom_format"] == "CycloneDX"

    def test_sbom_serial_number(self, req_dir):
        (req_dir / "requirements.txt").write_text("flask==2.3.0\n")
        sbom = generate_sbom(str(req_dir))
        assert sbom.serial_number.startswith("urn:uuid:sbom-")
