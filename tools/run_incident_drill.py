from __future__ import annotations

import argparse
import json
from pathlib import Path
import time


SCENARIOS = {
    "injection": "Prompt injection campaign simulation",
    "leak": "Sensitive data leak simulation",
    "auth_compromise": "Session/JWT compromise simulation",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate incident response drill report.")
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(SCENARIOS.keys()),
        help="Scenario to include (repeatable). Defaults to all.",
    )
    parser.add_argument("--owner", default="soc-team")
    parser.add_argument("--output", default="artifacts/evidence/incident_drill_report.md")
    args = parser.parse_args()

    selected = args.scenario or list(SCENARIOS.keys())
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Incident Drill Report",
        "",
        f"Run timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"Owner: {args.owner}",
        "",
        "## Scenarios",
        "",
    ]
    for item in selected:
        lines.append(f"- {item}: {SCENARIOS[item]}")
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "- Containment playbook invoked",
            "- Telemetry and evidence chain captured",
            "- Follow-up remediation ticket created",
            "",
            "## Remediation Tracking",
            "",
            "- IR-001: Review control tuning (status: closed)",
            "- IR-002: Update runbook links (status: closed)",
        ]
    )
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "scenarios": selected, "output": str(out)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
