"""
SkillStore — Local skill storage and injection for GuardianAI agents.

Manages the skill cache directory and provides utilities to inject
learned skills into agent execution contexts.
"""

import json
from pathlib import Path
from datetime import datetime

SKILL_CACHE_DIR = Path(__file__).resolve().parent / "skill_cache"


class SkillStore:
    """Manages locally cached Moltuni skills."""

    def __init__(self, cache_dir: Path = None):
        self.cache_dir = cache_dir or SKILL_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def list_skills(self) -> list[dict]:
        """List all cached skills with metadata."""
        skills = []
        for f in self.cache_dir.glob("*.json"):
            if f.name.startswith("_"):
                continue
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    skills.append({
                        "slug": data.get("slug", f.stem),
                        "name": data.get("name", f.stem),
                        "category": data.get("category", []),
                        "version": data.get("version", "?"),
                        "cached_at": data.get("cached_at", "unknown"),
                        "has_code": bool(data.get("code")),
                    })
            except (json.JSONDecodeError, KeyError):
                continue
        return skills

    def get_skill(self, slug: str) -> dict | None:
        """Get full skill data by slug."""
        path = self.cache_dir / f"{slug}.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, KeyError):
            return None

    def save_skill(self, skill: dict):
        """Save or update a skill in the cache."""
        slug = skill.get("slug", "unknown")
        path = self.cache_dir / f"{slug}.json"
        skill["cached_at"] = datetime.now().isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(skill, f, indent=2)

    def inject_skill(self, agent, skill_slug: str) -> bool:
        """
        Inject a cached skill into an agent's skill set.
        Returns True if successful.
        """
        skill = self.get_skill(skill_slug)
        if not skill:
            print(f"  ⚠️  Skill '{skill_slug}' not found in cache")
            return False

        agent.learn_skill(skill)
        return True

    def inject_skills_by_category(self, agent, categories: list[str]) -> int:
        """
        Inject all cached skills matching the given categories into an agent.
        Returns count of injected skills.
        """
        count = 0
        for skill_data in self.list_skills():
            skill_cats = set(skill_data.get("category", []))
            if skill_cats & set(categories):
                full_skill = self.get_skill(skill_data["slug"])
                if full_skill:
                    agent.learn_skill(full_skill)
                    count += 1
        return count

    def get_skill_knowledge(self, categories: list[str] = None) -> str:
        """
        Extract aggregated knowledge from cached skills as a text prompt.
        Useful for injecting into agent system prompts.
        """
        knowledge_parts = []
        skills = self.list_skills()

        for skill_meta in skills:
            if categories:
                if not set(skill_meta.get("category", [])) & set(categories):
                    continue

            full = self.get_skill(skill_meta["slug"])
            if full and full.get("code"):
                knowledge_parts.append(
                    f"### Skill: {full.get('name', '?')}\n"
                    f"Category: {', '.join(full.get('category', []))}\n"
                    f"```\n{full['code'][:2000]}\n```\n"
                )

        if not knowledge_parts:
            return "No relevant skills found in cache."

        return (
            "## Learned Skills from Moltuni\n\n"
            + "\n".join(knowledge_parts)
        )

    def print_summary(self):
        """Print a summary of cached skills."""
        skills = self.list_skills()
        if not skills:
            print("  📦 Skill cache is empty. Run --learn to fetch from Moltuni.")
            return

        print(f"\n  📦 Skill Cache: {len(skills)} skills")
        print(f"  {'─'*45}")
        for s in skills:
            cats = ", ".join(s["category"]) if s["category"] else "uncategorized"
            code_icon = "📝" if s["has_code"] else "📄"
            print(f"  {code_icon} {s['name']} (v{s['version']}) [{cats}]")
        print()
