"""
Query Hugging Face and GitHub APIs for AI safety, prompt injection,
agent memory poisoning, and jailbreak benchmark datasets.
"""
import urllib.request
import urllib.parse
import json
import os
import sys

def query_hf_datasets(query, limit=10):
    url = f"https://huggingface.co/api/datasets?search={urllib.parse.quote(query)}&limit={limit}"
    req = urllib.request.Request(url, headers={"User-Agent": "GuardianAI-Audit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"Error querying Hugging Face for '{query}': {e}", file=sys.stderr)
        return []

def query_github_repos(query, limit=10):
    url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query)}&sort=stars&order=desc&per_page={limit}"
    req = urllib.request.Request(url, headers={"User-Agent": "GuardianAI-Audit/1.0", "Accept": "application/vnd.github.v3+json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            return data.get("items", [])
    except Exception as e:
        print(f"Error querying GitHub for '{query}': {e}", file=sys.stderr)
        return []

if __name__ == "__main__":
    print("==================================================================")
    print("      HUGGING FACE & GITHUB BENCHMARK DISCOVERY FOR GUARDIANAI     ")
    print("==================================================================")

    topics = [
        "prompt-injection",
        "jailbreak",
        "agent memory poisoning",
        "llm guardrails",
    ]

    print("\n--- HUGGING FACE DATASETS ---")
    for t in topics:
        results = query_hf_datasets(t, limit=5)
        print(f"\n[Hugging Face] Topic: '{t}' ({len(results)} found)")
        for item in results:
            dataset_id = item.get("id")
            downloads = item.get("downloads", 0)
            likes = item.get("likes", 0)
            print(f"  * https://huggingface.co/datasets/{dataset_id} (downloads: {downloads}, likes: {likes})")

    print("\n--- GITHUB REPOSITORIES ---")
    gh_topics = [
        "prompt injection benchmark",
        "jailbreak llm benchmark",
        "ai agent memory poisoning",
    ]
    for gt in gh_topics:
        gh_results = query_github_repos(gt, limit=5)
        print(f"\n[GitHub] Topic: '{gt}' ({len(gh_results)} found)")
        for repo in gh_results:
            full_name = repo.get("full_name")
            stars = repo.get("stargazers_count", 0)
            desc = (repo.get("description") or "")[:80]
            print(f"  * https://github.com/{full_name} ({stars} stars) - {desc}")
