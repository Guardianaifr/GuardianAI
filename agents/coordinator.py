"""
CoordinatorAgent — Orchestrates all specialist agents.

Owns Tasks from 30-Day Plan:
  Day 7: Review roadmaps, prioritize critical path, commit targets, assign owners
  Weekly: Friday check-ins, status tracking
"""

import json
from pathlib import Path
from datetime import datetime
from agents.base_agent import BaseAgent, Task, PROJECT_ROOT


class CoordinatorAgent(BaseAgent):
    """Coordinator — orchestrates all specialist agents."""

    def __init__(self):
        super().__init__(
            name="coordinator",
            role="Coordinator (All)",
            skill_categories=["automation", "productivity"],
        )
        self._specialists = []

    def _init_tasks(self):
        self.tasks = [
            Task("CO-001", "Review all roadmaps from specialist agents", "Day 7"),
            Task("CO-002", "Prioritize critical path", "Day 7"),
            Task("CO-003", "Commit to 30-day targets", "Day 7"),
            Task("CO-004", "Assign owners and set daily standups", "Day 7"),
            Task("CO-005", "Run weekly check-in (Friday sync)", "Weekly"),
        ]

    def register_specialists(self, agents: list):
        """Register specialist agents for orchestration."""
        self._specialists = agents

    def execute_task(self, task_id: str) -> dict:
        handlers = {
            "CO-001": self._review_roadmaps,
            "CO-002": self._prioritize,
            "CO-003": self._commit_targets,
            "CO-004": self._assign_owners,
            "CO-005": self._weekly_checkin,
        }
        handler = handlers.get(task_id)
        if not handler:
            return {"error": f"Unknown task: {task_id}"}
        return handler()

    def run_all_specialists(self, dry_run=False):
        """Run all registered specialist agents."""
        print(f"\n{'='*60}")
        print(f"  🎯 COORDINATOR: Running all specialists")
        print(f"  Agents: {len(self._specialists)}")
        print(f"{'='*60}")

        all_results = {}
        for agent in self._specialists:
            results = agent.run_all_tasks(dry_run=dry_run)
            all_results[agent.name] = results

        # Generate combined report
        self._generate_combined_report(all_results)
        return all_results

    def show_all_status(self):
        """Show status for all agents including self."""
        self.print_status()
        for agent in self._specialists:
            agent.print_status()

    def _review_roadmaps(self) -> dict:
        """CO-001: Collect and review all specialist reports."""
        print("    📊 Reviewing specialist roadmaps...")
        summary = {}
        for agent in self._specialists:
            status = agent.report_status()
            summary[agent.name] = {
                "role": status["role"],
                "progress": status["progress"],
                "done": status["summary"]["done"],
                "pending": status["summary"]["pending"],
                "blocked": status["summary"]["blocked"],
            }
        self._save_report("roadmap_review", summary)
        return summary

    def _prioritize(self) -> dict:
        """CO-002: Define critical path."""
        critical_path = [
            {"phase": 1, "agent": "lead_engineer", "tasks": "LE-001 to LE-004", "desc": "Assessment"},
            {"phase": 1, "agent": "qa_lead", "tasks": "QA-001 to QA-004", "desc": "Plan validation"},
            {"phase": 1, "agent": "perf_engineer", "tasks": "PE-001 to PE-004", "desc": "Profile & plan"},
            {"phase": 1, "agent": "devops_security", "tasks": "DS-001 to DS-004", "desc": "Audit"},
            {"phase": 2, "agent": "qa_lead", "tasks": "QA-005 to QA-008", "desc": "Build test corpus"},
            {"phase": 2, "agent": "perf_engineer", "tasks": "PE-005 to PE-007", "desc": "Instrument & benchmark"},
            {"phase": 2, "agent": "lead_engineer", "tasks": "LE-005 to LE-008", "desc": "Code audit deep dive"},
            {"phase": 3, "agent": "qa_lead", "tasks": "QA-009", "desc": "Run benchmark"},
            {"phase": 3, "agent": "perf_engineer", "tasks": "PE-008 to PE-010", "desc": "Optimize"},
            {"phase": 3, "agent": "devops_security", "tasks": "DS-009 to DS-013", "desc": "Harden"},
            {"phase": 4, "agent": "qa_lead", "tasks": "QA-010", "desc": "Publish validation"},
            {"phase": 4, "agent": "lead_engineer", "tasks": "LE-009 to LE-011", "desc": "Quality checklist"},
        ]
        self._save_report("critical_path", {"phases": critical_path})
        return {"phases": critical_path}

    def _commit_targets(self) -> dict:
        """CO-003: Define 30-day commitment."""
        targets = {
            "must_have": [
                "Validation report published (FP/FN/precision/recall)",
                "Latency optimized (p95 <50ms)",
                "Operations formalized (TTL, backups, monitoring)",
                "Code coverage ≥80%",
                "Security review completed",
            ],
            "should_have": [
                "Documentation complete",
                "Multi-instance plan drafted",
                "Threat modeling initiated",
            ],
        }
        self._save_report("targets", targets)
        return targets

    def _assign_owners(self) -> dict:
        """CO-004: Map tasks to owners."""
        assignments = {}
        for agent in self._specialists:
            assignments[agent.name] = {
                "role": agent.role,
                "task_count": len(agent.tasks),
                "tasks": [f"{t.task_id}: {t.description}" for t in agent.tasks],
            }
        self._save_report("assignments", assignments)
        return assignments

    def _weekly_checkin(self) -> dict:
        """CO-005: Generate weekly check-in report."""
        print("    📋 Generating weekly check-in...")
        checkin = {"timestamp": datetime.now().isoformat(), "agents": {}}
        total_done = 0
        total_tasks = 0

        for agent in self._specialists:
            s = agent.report_status()
            checkin["agents"][agent.name] = {
                "progress": s["progress"],
                "blocked": s["summary"]["blocked"],
                "completed_this_week": s["summary"]["done"],
            }
            total_done += s["summary"]["done"]
            total_tasks += len(agent.tasks)

        checkin["overall_progress"] = f"{total_done}/{total_tasks} ({total_done/total_tasks*100:.0f}%)" if total_tasks else "0%"
        self._save_report("weekly_checkin", checkin)
        return checkin

    def _generate_combined_report(self, results: dict):
        """Generate a combined status report."""
        lines = [
            "# GuardianAI 30-Day Plan — Combined Status",
            f"\nGenerated: {datetime.now():%Y-%m-%d %H:%M}",
            "\n## Agent Summary",
            "\n| Agent | Role | Tasks | Done | Pending | Blocked |",
            "|-------|------|-------|------|---------|---------|",
        ]
        for agent in self._specialists:
            s = agent.report_status()
            sm = s["summary"]
            lines.append(f"| {agent.name} | {agent.role} | {len(agent.tasks)} | "
                        f"{sm['done']} | {sm['pending']} | {sm['blocked']} |")

        total = sum(len(a.tasks) for a in self._specialists)
        done = sum(a.report_status()["summary"]["done"] for a in self._specialists)
        lines.append(f"\n**Overall: {done}/{total} tasks complete ({done/total*100:.0f}%)**" if total else "")

        path = PROJECT_ROOT / "agents" / "reports" / "combined_status.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")

    def _save_report(self, name: str, data: dict):
        rd = PROJECT_ROOT / "agents" / "reports" / self.name
        rd.mkdir(parents=True, exist_ok=True)
        p = rd / f"{name}_{datetime.now():%Y%m%d_%H%M%S}.json"
        with open(p, "w") as f: json.dump(data, f, indent=2)
        print(f"    💾 Report: {p.name}")
