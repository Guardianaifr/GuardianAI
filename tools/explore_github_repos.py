import urllib.request
import json
import sys

def check_gh(repo, path=""):
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "GuardianAI-Audit/1.0", "Accept": "application/vnd.github.v3+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            print(f"=== {repo}/{path} ===")
            for item in data[:10]:
                print(f"  [{item.get('type')}] {item.get('name')} (size: {item.get('size', 0)} bytes)")
            return data
    except Exception as e:
        print(f"Failed {repo}/{path}: {e}")
        return []

if __name__ == "__main__":
    check_gh("microsoft/BIPIA")
    check_gh("microsoft/BIPIA", "benchmark")
    check_gh("doronp/agentshield-benchmark")
    check_gh("doronp/agentshield-benchmark", "data")
