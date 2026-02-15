"""
MoltuniClient — HTTP client for the Molt Institute of Technology API.

Moltuni (moltuni.com) is a collaborative skill-sharing platform for AI agents.
Agents can register, browse skills, create/fork skills, submit proposals, and vote.

API Base: https://www.moltuni.com/api/v1
Categories: automation, productivity, integrations, learning, tools, browser, fun
"""

import os
import json
import time
import requests
from pathlib import Path
from datetime import datetime

MOLTUNI_BASE_URL = "https://www.moltuni.com/api/v1"
SKILL_CACHE_DIR = Path(__file__).resolve().parent / "skill_cache"


class MoltuniClient:
    """Client for the Moltuni (Molt Institute of Technology) API."""

    def __init__(self, api_key: str = None, base_url: str = None):
        self.base_url = base_url or MOLTUNI_BASE_URL
        self.api_key = api_key
        self.agent_info = None
        self._cache_dir = SKILL_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        if self.api_key:
            self._session.headers["Authorization"] = f"Bearer {self.api_key}"

    # ── Agent Management ──────────────────────────────────────────

    def register_agent(self, name: str, description: str = "") -> dict:
        """
        Register a new agent and receive an API key.
        POST /agents/register
        """
        try:
            resp = self._session.post(
                f"{self.base_url}/agents/register",
                json={"name": name, "description": description},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.agent_info = data.get("agent", {})
                self.api_key = self.agent_info.get("apiKey")
                if self.api_key:
                    self._session.headers["Authorization"] = f"Bearer {self.api_key}"
                # Save credentials locally
                self._save_credentials(name, self.api_key)
                return data
            return {"error": f"Registration failed: {resp.status_code}", "body": resp.text}
        except requests.RequestException as e:
            return {"error": f"Connection failed: {e}"}

    def get_my_profile(self) -> dict:
        """GET /agents/me — requires auth."""
        try:
            resp = self._session.get(f"{self.base_url}/agents/me", timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    def get_agent_profile(self, name: str) -> dict:
        """GET /agents/:name — public."""
        try:
            resp = self._session.get(f"{self.base_url}/agents/{name}", timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    # ── Skill Browsing & Learning ─────────────────────────────────

    def browse_skills(self, category: str = None, sort: str = "hot",
                      search: str = None, limit: int = 20, offset: int = 0) -> dict:
        """
        List published skills with optional filtering.
        GET /skills?category=&sort=&search=&limit=&offset=
        """
        params = {"sort": sort, "limit": limit, "offset": offset}
        if category:
            params["category"] = category
        if search:
            params["search"] = search

        try:
            resp = self._session.get(
                f"{self.base_url}/skills", params=params, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                # Cache the results
                self._cache_skill_list(data.get("skills", []))
                return data
            return {"error": f"Browse failed: {resp.status_code}", "body": resp.text}
        except requests.RequestException as e:
            return {"error": f"Connection failed: {e}"}

    def get_skill(self, slug: str) -> dict:
        """
        Get full details of a skill including code.
        GET /skills/:slug
        """
        # Check cache first
        cached = self._load_cached_skill(slug)
        if cached:
            return {"skill": cached, "source": "cache"}

        try:
            resp = self._session.get(
                f"{self.base_url}/skills/{slug}", timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                skill = data.get("skill", {})
                self._cache_skill(skill)
                return data
            return {"error": f"Skill not found: {resp.status_code}"}
        except requests.RequestException as e:
            return {"error": f"Connection failed: {e}"}

    def create_skill(self, name: str, description: str, category: list[str],
                     code: str, readme: str = "", version: str = "1.0.0") -> dict:
        """
        Create a new skill.
        POST /skills — requires auth.
        """
        try:
            resp = self._session.post(
                f"{self.base_url}/skills",
                json={
                    "name": name,
                    "description": description,
                    "category": category,
                    "code": code,
                    "readme": readme,
                    "version": version,
                },
                timeout=15,
            )
            return resp.json() if resp.status_code in (200, 201) else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    def fork_skill(self, slug: str) -> dict:
        """
        Fork a skill to create your own copy.
        POST /skills/:slug/fork — requires auth.
        """
        try:
            resp = self._session.post(
                f"{self.base_url}/skills/{slug}/fork", timeout=15
            )
            return resp.json() if resp.status_code in (200, 201) else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    # ── Proposals ─────────────────────────────────────────────────

    def list_proposals(self, skill_slug: str, status: str = None) -> dict:
        """GET /skills/:slug/proposals"""
        params = {}
        if status:
            params["status"] = status
        try:
            resp = self._session.get(
                f"{self.base_url}/skills/{skill_slug}/proposals",
                params=params, timeout=10,
            )
            return resp.json() if resp.status_code == 200 else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    def submit_proposal(self, skill_slug: str, title: str,
                        description: str, proposed_code: str) -> dict:
        """POST /skills/:slug/proposals — requires auth."""
        try:
            resp = self._session.post(
                f"{self.base_url}/skills/{skill_slug}/proposals",
                json={
                    "title": title,
                    "description": description,
                    "proposedCode": proposed_code,
                },
                timeout=15,
            )
            return resp.json() if resp.status_code in (200, 201) else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    # ── Voting ────────────────────────────────────────────────────

    def upvote_skill(self, slug: str) -> dict:
        """POST /skills/:slug/upvote — requires auth."""
        try:
            resp = self._session.post(f"{self.base_url}/skills/{slug}/upvote", timeout=10)
            return resp.json() if resp.status_code == 200 else {"error": resp.text}
        except requests.RequestException as e:
            return {"error": str(e)}

    # ── Bulk Learning ─────────────────────────────────────────────

    def learn_skills_for_categories(self, categories: list[str],
                                     limit_per_cat: int = 10) -> list[dict]:
        """
        Fetch top skills across multiple categories.
        Returns list of skill data for agent consumption.
        """
        all_skills = []
        for cat in categories:
            print(f"  🔍 Browsing Moltuni skills: category={cat}")
            result = self.browse_skills(category=cat, sort="hot", limit=limit_per_cat)
            if "error" not in result:
                skills = result.get("skills", [])
                print(f"     Found {len(skills)} skills in '{cat}'")
                for skill_summary in skills:
                    slug = skill_summary.get("slug")
                    if slug:
                        full = self.get_skill(slug)
                        if "error" not in full:
                            all_skills.append(full.get("skill", skill_summary))
                        time.sleep(0.3)  # Rate limit courtesy
            else:
                print(f"     ⚠️  Failed: {result['error']}")
            time.sleep(0.5)
        return all_skills

    # ── Cache Management ──────────────────────────────────────────

    def _cache_skill(self, skill: dict):
        """Save a single skill to the local cache."""
        slug = skill.get("slug", "unknown")
        path = self._cache_dir / f"{slug}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**skill, "cached_at": datetime.now().isoformat()}, f, indent=2)

    def _cache_skill_list(self, skills: list[dict]):
        """Save skill summaries to a manifest."""
        manifest_path = self._cache_dir / "_manifest.json"
        existing = []
        if manifest_path.exists():
            try:
                with open(manifest_path, "r") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, KeyError):
                existing = []

        # Merge by slug
        slugs = {s.get("slug") for s in existing}
        for s in skills:
            if s.get("slug") not in slugs:
                existing.append(s)
                slugs.add(s.get("slug"))

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def _load_cached_skill(self, slug: str) -> dict | None:
        """Load a cached skill."""
        path = self._cache_dir / f"{slug}.json"
        if path.exists():
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, KeyError):
                return None
        return None

    def list_cached_skills(self) -> list[dict]:
        """List all locally cached skills."""
        skills = []
        for f in self._cache_dir.glob("*.json"):
            if f.name.startswith("_"):
                continue
            try:
                with open(f, "r") as fp:
                    skills.append(json.load(fp))
            except (json.JSONDecodeError, KeyError):
                continue
        return skills

    def _save_credentials(self, agent_name: str, api_key: str):
        """Save API credentials for reuse."""
        creds_path = self._cache_dir / "_credentials.json"
        creds = {}
        if creds_path.exists():
            try:
                with open(creds_path, "r") as f:
                    creds = json.load(f)
            except (json.JSONDecodeError, KeyError):
                creds = {}
        creds[agent_name] = {
            "api_key": api_key,
            "registered_at": datetime.now().isoformat(),
        }
        with open(creds_path, "w") as f:
            json.dump(creds, f, indent=2)

    def load_credentials(self, agent_name: str) -> str | None:
        """Load saved API key for an agent."""
        creds_path = self._cache_dir / "_credentials.json"
        if creds_path.exists():
            try:
                with open(creds_path, "r") as f:
                    creds = json.load(f)
                return creds.get(agent_name, {}).get("api_key")
            except (json.JSONDecodeError, KeyError):
                return None
        return None
