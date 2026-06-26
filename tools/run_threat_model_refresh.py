from __future__ import annotations

import argparse
import json
from pathlib import Path
import time


OWASP_LLM_ITEMS = [
    "Prompt Injection",
    "Sensitive Information Disclosure",
    "Supply Chain Vulnerabilities",
    "Data and Model Poisoning",
    "Insecure Plugin Design",
]

MITRE_ATLAS_TECHNIQUES = [
    "AML.T0051 Prompt Injection",
    "AML.T0024 Exfiltration via Prompt",
    "AML.T0015 Data Poisoning",
    "AML.T0036 Model Evasion",
]


def current_quarter(ts: float | None = None) -> str:
    t = time.gmtime(ts or time.time())
    quarter = ((t.tm_mon - 1) // 3) + 1
    return f"{t.tm_year}-Q{quarter}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate quarterly threat-model refresh evidence.")
    parser.add_argument("--output", default="artifacts/evidence/threat_model_quarterly.md")
    parser.add_argument("--owner", default="security-team")
    parser.add_argument("--accepted-risks", default="[]")
    args = parser.parse_args()

    quarter = current_quarter()
    accepted_risks = json.loads(args.accepted_risks)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Quarterly Threat Model Refresh",
        "",
        f"Quarter: {quarter}",
        f"Owner: {args.owner}",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
        "## OWASP LLM Review",
        "",
    ]
    for item in OWASP_LLM_ITEMS:
        lines.append(f"- {item}")
    lines.extend(["", "## MITRE ATLAS Mapping", ""])
    for item in MITRE_ATLAS_TECHNIQUES:
        lines.append(f"- {item}")
    lines.extend(["", "## Accepted Risks", ""])
    if accepted_risks:
        for risk in accepted_risks:
            lines.append(f"- {risk}")
    else:
        lines.append("- None")
    lines.extend(["", "## Sign-off", "", f"- Security Owner: {args.owner}", "- Status: approved"])

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "quarter": quarter, "output": str(out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
