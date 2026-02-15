"""
BaseAgent — Abstract base class for all GuardianAI specialist agents.

Each agent has:
  - A role and name
  - A set of tasks from the 30-day plan
  - Ability to learn skills from Moltuni
  - Status reporting (standup-style)
"""

import os
import json
import yaml
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path

# Resolve project root relative to this file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = Path(__file__).resolve().parent


class Task:
    """Represents a single task from the 30-day plan."""

    def __init__(self, task_id: str, description: str, day: str, status: str = "pending"):
        self.task_id = task_id
        self.description = description
        self.day = day
        self.status = status  # pending | in_progress | done | blocked
        self.result = None
        self.started_at = None
        self.completed_at = None

    def start(self):
        self.status = "in_progress"
        self.started_at = datetime.now().isoformat()

    def complete(self, result=None):
        self.status = "done"
        self.result = result
        self.completed_at = datetime.now().isoformat()

    def block(self, reason: str):
        self.status = "blocked"
        self.result = reason

    def to_dict(self):
        return {
            "task_id": self.task_id,
            "description": self.description,
            "day": self.day,
            "status": self.status,
            "result": self.result,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class BaseAgent(ABC):
    """Abstract base class for all GuardianAI specialist agents."""

    def __init__(self, name: str, role: str, skill_categories: list[str] = None):
        self.name = name
        self.role = role
        self.skill_categories = skill_categories or []
        self.skills = []  # Skills learned from Moltuni
        self.tasks: list[Task] = []
        self.created_at = datetime.now().isoformat()
        self._state_file = AGENTS_DIR / "state" / f"{self.name}_state.json"

        # Initialize tasks for this agent
        self._init_tasks()

        # Load any previously saved state
        self._load_state()

    @abstractmethod
    def _init_tasks(self):
        """Initialize the tasks this agent owns from the 30-day plan."""
        pass

    @abstractmethod
    def execute_task(self, task_id: str) -> dict:
        """Execute a specific task. Returns result dict."""
        pass

    def run_all_tasks(self, dry_run: bool = False) -> list[dict]:
        """Execute all pending tasks in order."""
        results = []
        print(f"\n{'='*60}")
        print(f"  🤖 {self.name} ({self.role})")
        print(f"  Tasks: {len(self.tasks)} total, "
              f"{sum(1 for t in self.tasks if t.status == 'pending')} pending")
        print(f"{'='*60}\n")

        for task in self.tasks:
            if task.status == "done":
                print(f"  ⏭️  [{task.task_id}] Already done: {task.description}")
                continue

            if dry_run:
                print(f"  🔍 [{task.task_id}] Would execute: {task.description}")
                results.append({"task_id": task.task_id, "dry_run": True})
                continue

            print(f"\n  ▶️  [{task.task_id}] Executing: {task.description}")
            task.start()

            try:
                result = self.execute_task(task.task_id)
                task.complete(result)
                print(f"  ✅ [{task.task_id}] Done")
                results.append(task.to_dict())
            except Exception as e:
                task.block(str(e))
                print(f"  ❌ [{task.task_id}] Failed: {e}")
                results.append(task.to_dict())

        self._save_state()
        return results

    def learn_skill(self, skill_data: dict):
        """Add a learned skill from Moltuni to this agent."""
        self.skills.append({
            "slug": skill_data.get("slug"),
            "name": skill_data.get("name"),
            "category": skill_data.get("category", []),
            "code": skill_data.get("code"),
            "learned_at": datetime.now().isoformat(),
        })
        print(f"  📚 {self.name} learned skill: {skill_data.get('name')}")

    def report_status(self) -> dict:
        """Generate a standup-style status report."""
        total = len(self.tasks)
        done = sum(1 for t in self.tasks if t.status == "done")
        in_progress = sum(1 for t in self.tasks if t.status == "in_progress")
        blocked = sum(1 for t in self.tasks if t.status == "blocked")
        pending = sum(1 for t in self.tasks if t.status == "pending")

        report = {
            "agent": self.name,
            "role": self.role,
            "timestamp": datetime.now().isoformat(),
            "progress": f"{done}/{total} tasks ({(done/total*100):.0f}%)" if total else "0/0",
            "skills_learned": len(self.skills),
            "summary": {
                "done": done,
                "in_progress": in_progress,
                "blocked": blocked,
                "pending": pending,
            },
            "tasks": [t.to_dict() for t in self.tasks],
        }
        return report

    def print_status(self):
        """Pretty-print the status report."""
        r = self.report_status()
        print(f"\n┌─── 🤖 {r['agent']} ({r['role']}) ───")
        print(f"│  Progress: {r['progress']}")
        print(f"│  Skills: {r['skills_learned']} learned")
        print(f"│  ✅ Done: {r['summary']['done']}  "
              f"🔄 In Progress: {r['summary']['in_progress']}  "
              f"⏳ Pending: {r['summary']['pending']}  "
              f"🚫 Blocked: {r['summary']['blocked']}")

        for t in self.tasks:
            icon = {"done": "✅", "in_progress": "🔄", "pending": "⏳", "blocked": "🚫"}
            print(f"│  {icon.get(t.status, '?')} [{t.day}] {t.description}")

        print(f"└{'─'*50}\n")

    def _save_state(self):
        """Persist agent state to disk."""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "tasks": [t.to_dict() for t in self.tasks],
            "skills": self.skills,
            "saved_at": datetime.now().isoformat(),
        }
        with open(self._state_file, "w") as f:
            json.dump(state, f, indent=2)

    def _load_state(self):
        """Load previously saved state if it exists."""
        if self._state_file.exists():
            try:
                with open(self._state_file, "r") as f:
                    state = json.load(f)
                # Restore task statuses
                saved_tasks = {t["task_id"]: t for t in state.get("tasks", [])}
                for task in self.tasks:
                    if task.task_id in saved_tasks:
                        saved = saved_tasks[task.task_id]
                        task.status = saved.get("status", "pending")
                        task.result = saved.get("result")
                        task.started_at = saved.get("started_at")
                        task.completed_at = saved.get("completed_at")
                # Restore skills
                self.skills = state.get("skills", [])
            except (json.JSONDecodeError, KeyError):
                pass  # Corrupted state, start fresh

    def _find_task(self, task_id: str) -> Task | None:
        """Find a task by ID."""
        for t in self.tasks:
            if t.task_id == task_id:
                return t
        return None

    def _analyze_file(self, filepath: str) -> dict:
        """Basic file analysis — line count, size, extension."""
        p = Path(filepath)
        if not p.exists():
            return {"error": f"File not found: {filepath}"}
        stat = p.stat()
        lines = 0
        if p.suffix in ('.py', '.yaml', '.yml', '.json', '.md', '.txt'):
            try:
                lines = len(p.read_text(encoding='utf-8', errors='ignore').splitlines())
            except Exception:
                pass
        return {
            "path": str(p),
            "size_bytes": stat.st_size,
            "lines": lines,
            "extension": p.suffix,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }

    def _scan_directory(self, directory: str, extensions: list[str] = None) -> list[dict]:
        """Recursively scan a directory for files."""
        results = []
        p = Path(directory)
        if not p.exists():
            return results
        for item in p.rglob("*"):
            if item.is_file():
                if extensions and item.suffix not in extensions:
                    continue
                if "__pycache__" in str(item) or ".git" in str(item):
                    continue
                results.append(self._analyze_file(str(item)))
        return results
