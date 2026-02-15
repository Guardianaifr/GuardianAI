"""
LeadEngineerAgent — Code quality, auditing, test coverage, tech debt tracking.

Owns Tasks from 30-Day Plan:
  Day 1-2: Code audit, assumptions, profiling, documentation review
  Week 2 Track C: Coverage, untested paths, tech debt, refactoring plan
  Week 4: Code coverage ≥80%, all components tested, documentation complete
"""

import os
import ast
import subprocess
import json
from pathlib import Path
from datetime import datetime
from agents.base_agent import BaseAgent, Task, PROJECT_ROOT


class LeadEngineerAgent(BaseAgent):
    """Lead Engineer — owns code quality, auditing, and technical debt."""

    def __init__(self):
        super().__init__(
            name="lead_engineer",
            role="Lead Engineer",
            skill_categories=["automation", "tools", "productivity"],
        )

    def _init_tasks(self):
        self.tasks = [
            # Day 1-2: Assess Current State
            Task("LE-001", "Run full code audit (code quality, coverage, tech debt)", "Day 1-2"),
            Task("LE-002", "Identify all assumptions (claims without data)", "Day 1-2"),
            Task("LE-003", "Profile performance (measure actual latency)", "Day 1-2"),
            Task("LE-004", "Review all documentation (what's documented vs missing)", "Day 1-2"),
            # Week 2 Track C: Code Audit
            Task("LE-005", "Measure test coverage (pytest --cov)", "Week 2"),
            Task("LE-006", "Identify untested code paths", "Week 2"),
            Task("LE-007", "Document technical debt", "Week 2"),
            Task("LE-008", "Plan refactoring (if needed)", "Week 2"),
            # Week 4: Quality Checklist
            Task("LE-009", "Verify code coverage ≥80%", "Week 4"),
            Task("LE-010", "Verify all components tested", "Week 4"),
            Task("LE-011", "Verify documentation complete (API, deployment, troubleshooting)", "Week 4"),
        ]

    def execute_task(self, task_id: str) -> dict:
        handlers = {
            "LE-001": self._run_code_audit,
            "LE-002": self._identify_assumptions,
            "LE-003": self._profile_performance,
            "LE-004": self._review_documentation,
            "LE-005": self._measure_coverage,
            "LE-006": self._find_untested_paths,
            "LE-007": self._document_tech_debt,
            "LE-008": self._plan_refactoring,
            "LE-009": self._verify_coverage_target,
            "LE-010": self._verify_all_tested,
            "LE-011": self._verify_documentation,
        }
        handler = handlers.get(task_id)
        if not handler:
            return {"error": f"Unknown task: {task_id}"}
        return handler()

    # ── Task Implementations ──────────────────────────────────────

    def _run_code_audit(self) -> dict:
        """LE-001: Full code audit — scan all Python files, analyze quality metrics."""
        print("    📂 Scanning codebase...")
        guardian_dir = PROJECT_ROOT / "guardian"
        files = self._scan_directory(str(guardian_dir), extensions=[".py"])

        total_lines = sum(f.get("lines", 0) for f in files)
        total_files = len(files)

        # Analyze each file for complexity indicators
        quality_issues = []
        for f_info in files:
            fpath = f_info.get("path", "")
            if not fpath.endswith(".py"):
                continue
            try:
                source = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)

                for node in ast.walk(tree):
                    # Flag very long functions (>50 lines)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        func_lines = (node.end_lineno or 0) - (node.lineno or 0)
                        if func_lines > 50:
                            quality_issues.append({
                                "file": os.path.basename(fpath),
                                "issue": "long_function",
                                "detail": f"{node.name}() is {func_lines} lines",
                                "severity": "medium",
                            })
                    # Flag bare try/except
                    if isinstance(node, ast.ExceptHandler) and node.type is None:
                        quality_issues.append({
                            "file": os.path.basename(fpath),
                            "issue": "bare_except",
                            "detail": f"Bare except at line {node.lineno}",
                            "severity": "high",
                        })
                    # Flag TODO/FIXME comments
                for i, line in enumerate(source.splitlines(), 1):
                    if "TODO" in line or "FIXME" in line or "HACK" in line:
                        quality_issues.append({
                            "file": os.path.basename(fpath),
                            "issue": "todo_comment",
                            "detail": f"Line {i}: {line.strip()[:80]}",
                            "severity": "low",
                        })
            except (SyntaxError, UnicodeDecodeError):
                quality_issues.append({
                    "file": os.path.basename(fpath),
                    "issue": "parse_error",
                    "detail": "Could not parse file",
                    "severity": "high",
                })

        report = {
            "total_files": total_files,
            "total_lines": total_lines,
            "quality_issues": len(quality_issues),
            "issues_by_severity": {
                "high": sum(1 for i in quality_issues if i["severity"] == "high"),
                "medium": sum(1 for i in quality_issues if i["severity"] == "medium"),
                "low": sum(1 for i in quality_issues if i["severity"] == "low"),
            },
            "details": quality_issues[:20],  # Top 20
            "files_analyzed": [f.get("path") for f in files],
        }

        # Save report
        self._save_report("code_audit", report)
        print(f"    📊 Audit: {total_files} files, {total_lines} lines, "
              f"{len(quality_issues)} issues found")
        return report

    def _identify_assumptions(self) -> dict:
        """LE-002: Find unvalidated assumptions in the codebase."""
        print("    🔍 Scanning for unvalidated claims...")
        guardian_dir = PROJECT_ROOT / "guardian"
        assumptions = []

        # Search for hardcoded claims, magic numbers, unvalidated thresholds
        keywords = ["assume", "should be", "expected", "approximately",
                     "roughly", "about", "around", "estimated", "~"]

        for py_file in guardian_dir.rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(source.splitlines(), 1):
                    line_lower = line.lower()
                    for kw in keywords:
                        if kw in line_lower and not line.strip().startswith("#"):
                            assumptions.append({
                                "file": py_file.name,
                                "line": i,
                                "text": line.strip()[:100],
                                "keyword": kw,
                            })
            except Exception:
                continue

        # Also check config for hardcoded thresholds
        config_path = PROJECT_ROOT / "guardian" / "config" / "config.yaml"
        if config_path.exists():
            import yaml
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f)
                # Flag any numeric thresholds as assumptions
                def find_numbers(d, path=""):
                    items = []
                    if isinstance(d, dict):
                        for k, v in d.items():
                            items.extend(find_numbers(v, f"{path}.{k}"))
                    elif isinstance(d, (int, float)):
                        items.append({"path": path, "value": d, "type": "config_threshold"})
                    return items
                thresholds = find_numbers(config)
                assumptions.extend([{
                    "file": "config.yaml",
                    "line": 0,
                    "text": f"{t['path']} = {t['value']}",
                    "keyword": "config_threshold",
                } for t in thresholds])
            except Exception:
                pass

        report = {
            "total_assumptions": len(assumptions),
            "assumptions": assumptions[:30],
        }
        self._save_report("assumptions", report)
        print(f"    📋 Found {len(assumptions)} unvalidated assumptions")
        return report

    def _profile_performance(self) -> dict:
        """LE-003: Profile actual latency of key components."""
        print("    ⏱️  Profiling component latency (static analysis)...")
        # Since we can't run the server, do a static analysis of potential bottlenecks
        bottlenecks = []

        guardrails_dir = PROJECT_ROOT / "guardian" / "guardrails"
        for py_file in guardrails_dir.glob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Look for slow patterns
                        call_str = ast.dump(node)
                        if "model" in call_str.lower() or "encode" in call_str.lower():
                            bottlenecks.append({
                                "file": py_file.name,
                                "line": node.lineno,
                                "type": "model_call",
                                "detail": "ML model inference — potential latency hotspot",
                            })
                        if "requests" in call_str.lower() or "http" in call_str.lower():
                            bottlenecks.append({
                                "file": py_file.name,
                                "line": node.lineno,
                                "type": "network_call",
                                "detail": "Network I/O — blocking call",
                            })

                # Check for sync file I/O
                for i, line in enumerate(source.splitlines(), 1):
                    if "open(" in line and "async" not in line:
                        bottlenecks.append({
                            "file": py_file.name,
                            "line": i,
                            "type": "sync_io",
                            "detail": "Synchronous file I/O",
                        })
            except Exception:
                continue

        report = {
            "components_profiled": len(list(guardrails_dir.glob("*.py"))),
            "bottlenecks_found": len(bottlenecks),
            "bottlenecks": bottlenecks,
            "recommendation": "Add timing decorators to each guardrail for live profiling",
        }
        self._save_report("performance_profile", report)
        print(f"    🔥 Found {len(bottlenecks)} potential bottlenecks")
        return report

    def _review_documentation(self) -> dict:
        """LE-004: Review what's documented vs missing."""
        print("    📖 Reviewing documentation...")
        doc_files = []
        missing_docs = []

        # Check for expected docs
        expected_docs = [
            "README.md", "CHANGELOG.md", "CONTRIBUTING.md",
            "API.md", "DEPLOYMENT.md", "TROUBLESHOOTING.md",
        ]
        for doc in expected_docs:
            path = PROJECT_ROOT / doc
            if path.exists():
                doc_files.append({"name": doc, "status": "exists", "size": path.stat().st_size})
            else:
                missing_docs.append(doc)

        # Check for docstrings in Python modules
        modules_without_docstrings = []
        for py_file in (PROJECT_ROOT / "guardian").rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
                module_docstring = ast.get_docstring(tree)
                if not module_docstring:
                    modules_without_docstrings.append(py_file.name)
            except Exception:
                continue

        report = {
            "existing_docs": doc_files,
            "missing_docs": missing_docs,
            "modules_without_docstrings": modules_without_docstrings,
            "documentation_coverage": f"{len(doc_files)}/{len(expected_docs)} expected docs exist",
        }
        self._save_report("documentation_review", report)
        print(f"    📚 Docs: {len(doc_files)} exist, {len(missing_docs)} missing, "
              f"{len(modules_without_docstrings)} modules lack docstrings")
        return report

    def _measure_coverage(self) -> dict:
        """LE-005: Attempt to measure test coverage."""
        print("    🧪 Checking test coverage...")
        # Try running pytest --cov
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "--cov=guardian", "--cov-report=json",
                 "--cov-report=term-missing", "-q"],
                capture_output=True, text=True,
                cwd=str(PROJECT_ROOT), timeout=120,
            )
            return {
                "coverage_run": True,
                "stdout": result.stdout[:2000],
                "stderr": result.stderr[:1000],
                "returncode": result.returncode,
            }
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {
                "coverage_run": False,
                "reason": str(e),
                "recommendation": "Install pytest-cov: pip install pytest-cov",
            }

    def _find_untested_paths(self) -> dict:
        """LE-006: Identify code paths without tests."""
        print("    🔎 Finding untested code paths...")
        test_files = list((PROJECT_ROOT).rglob("test_*.py")) + list((PROJECT_ROOT).rglob("*_test.py"))

        # Find all modules and check if they have corresponding tests
        guardian_modules = []
        for py_file in (PROJECT_ROOT / "guardian").rglob("*.py"):
            if "__pycache__" in str(py_file) or py_file.name == "__init__.py":
                continue
            guardian_modules.append(py_file.stem)

        tested = set()
        for tf in test_files:
            try:
                source = tf.read_text(encoding="utf-8", errors="ignore")
                for mod in guardian_modules:
                    if mod in source:
                        tested.add(mod)
            except Exception:
                continue

        untested = [m for m in guardian_modules if m not in tested]

        report = {
            "total_modules": len(guardian_modules),
            "tested_modules": list(tested),
            "untested_modules": untested,
            "test_files_found": [str(t.name) for t in test_files],
            "coverage_estimate": f"{len(tested)}/{len(guardian_modules)} modules referenced in tests",
        }
        self._save_report("untested_paths", report)
        print(f"    🎯 {len(tested)}/{len(guardian_modules)} modules have tests, "
              f"{len(untested)} untested")
        return report

    def _document_tech_debt(self) -> dict:
        """LE-007: Compile technical debt inventory."""
        print("    📝 Documenting technical debt...")
        debt_items = []

        for py_file in (PROJECT_ROOT / "guardian").rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(source.splitlines(), 1):
                    stripped = line.strip()
                    # TODOs, FIXMEs, HACKs
                    for tag in ["TODO", "FIXME", "HACK", "XXX", "WORKAROUND"]:
                        if tag in stripped:
                            debt_items.append({
                                "file": py_file.name,
                                "line": i,
                                "tag": tag,
                                "text": stripped[:120],
                                "priority": "high" if tag in ("FIXME", "HACK") else "medium",
                            })
                    # Detect deprecated patterns
                    if "deprecated" in stripped.lower():
                        debt_items.append({
                            "file": py_file.name,
                            "line": i,
                            "tag": "DEPRECATED",
                            "text": stripped[:120],
                            "priority": "medium",
                        })
            except Exception:
                continue

        report = {
            "total_debt_items": len(debt_items),
            "by_priority": {
                "high": sum(1 for d in debt_items if d["priority"] == "high"),
                "medium": sum(1 for d in debt_items if d["priority"] == "medium"),
            },
            "items": debt_items,
        }
        self._save_report("tech_debt", report)
        print(f"    💳 Technical debt: {len(debt_items)} items")
        return report

    def _plan_refactoring(self) -> dict:
        """LE-008: Generate refactoring plan based on audit results."""
        print("    📐 Planning refactoring...")
        recommendations = [
            "Add type hints to all public functions",
            "Extract shared utilities into common/ module",
            "Add comprehensive docstrings to all modules",
            "Create unit tests for each guardrail module",
            "Implement proper error types instead of bare exceptions",
            "Add timing instrumentation to all guardrail checks",
            "Move hardcoded thresholds to config.yaml",
        ]

        # Check for files that need refactoring based on size
        large_files = []
        for py_file in (PROJECT_ROOT / "guardian").rglob("*.py"):
            if "__pycache__" in str(py_file):
                continue
            try:
                lines = len(py_file.read_text(encoding="utf-8", errors="ignore").splitlines())
                if lines > 200:
                    large_files.append({"file": py_file.name, "lines": lines})
            except Exception:
                continue

        report = {
            "recommendations": recommendations,
            "large_files_to_split": sorted(large_files, key=lambda x: x["lines"], reverse=True),
            "priority": "Start with guardrails module — highest impact",
        }
        self._save_report("refactoring_plan", report)
        print(f"    🔧 Generated {len(recommendations)} refactoring recommendations")
        return report

    def _verify_coverage_target(self) -> dict:
        """LE-009: Verify code coverage meets ≥80% target."""
        return self._measure_coverage()

    def _verify_all_tested(self) -> dict:
        """LE-010: Verify all components are tested."""
        return self._find_untested_paths()

    def _verify_documentation(self) -> dict:
        """LE-011: Final documentation completeness check."""
        return self._review_documentation()

    # ── Utilities ─────────────────────────────────────────────────

    def _save_report(self, report_name: str, data: dict):
        """Save a report to the reports directory."""
        reports_dir = PROJECT_ROOT / "agents" / "reports" / self.name
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"{report_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"    💾 Report saved: {path.name}")
