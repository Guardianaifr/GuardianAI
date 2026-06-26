"""Verify Guardian output watermark signature on a JSON response body."""

from __future__ import annotations

import argparse
from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.output_watermark import OutputWatermarker  # noqa: E402


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Verify output watermark signature.")
    p.add_argument("--input", required=True, help="Path to response JSON file.")
    p.add_argument("--key", required=True, help="Watermark HMAC key.")
    p.add_argument("--field", default="_guardian_watermark", help="Watermark field name.")
    p.add_argument("--key-id", default="local-dev", help="Expected key identifier (metadata only).")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    body = Path(args.input).read_text(encoding="utf-8")
    verifier = OutputWatermarker(
        {
            "enabled": True,
            "field_name": args.field,
            "key": args.key,
            "key_id": args.key_id,
            "require_json_output": True,
        }
    )
    decision = verifier.verify(body)
    output = {
        "action": decision.action,
        "reason": decision.reason,
        "details": decision.details,
    }
    print(json.dumps(output, indent=2))
    return 0 if decision.action == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
