from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path


def _parse_date(value: str) -> dt.date:
    return dt.datetime.strptime(value, "%Y-%m-%d").date()


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate release on freshness of external security review.")
    parser.add_argument("--report", default="artifacts/security/external_security_review.json")
    parser.add_argument("--max-age-days", type=int, default=120)
    parser.add_argument("--max-open-critical", type=int, default=0)
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(json.dumps({"status": "failed", "reason": "report_missing", "report": str(report_path)}))
        return 1

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    review_date = _parse_date(payload.get("review_date", "1970-01-01"))
    open_critical = int(payload.get("open_critical_findings", 999))
    age_days = (dt.date.today() - review_date).days
    passed = age_days <= args.max_age_days and open_critical <= args.max_open_critical

    print(
        json.dumps(
            {
                "status": "ok" if passed else "failed",
                "review_date": str(review_date),
                "age_days": age_days,
                "open_critical_findings": open_critical,
                "max_age_days": args.max_age_days,
                "max_open_critical": args.max_open_critical,
            }
        )
    )
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
