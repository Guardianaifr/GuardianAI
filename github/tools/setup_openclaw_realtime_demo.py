import argparse
import json
from pathlib import Path

import yaml


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare Guardian config/profile for real-time OpenClaw demos")
    parser.add_argument("--target-url", required=True, help="OpenClaw base URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--upstream-key", default="", help="Optional upstream bearer key for OpenClaw")
    parser.add_argument("--source-config", default="guardian/config/config.yaml")
    parser.add_argument("--output-config", default="guardian/config/openclaw_realtime_demo.yaml")
    parser.add_argument("--profile-file", default="tools/openclaw_realtime_profile.json")
    parser.add_argument("--proxy-url", default="http://127.0.0.1:8081")
    parser.add_argument("--model", default="openclaw")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    root = Path(__file__).resolve().parent.parent

    source_config = (root / args.source_config).resolve()
    output_config = (root / args.output_config).resolve()
    profile_file = (root / args.profile_file).resolve()

    if not source_config.exists():
        raise SystemExit(f"Source config not found: {source_config}")

    with source_config.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    proxy_cfg = config.setdefault("proxy", {})
    proxy_cfg["target_url"] = args.target_url.rstrip("/")
    proxy_cfg["listen_port"] = 8081
    if args.upstream_key.strip():
        proxy_cfg["upstream_key"] = args.upstream_key.strip()
    else:
        proxy_cfg.pop("upstream_key", None)

    backend_cfg = config.setdefault("backend", {})
    backend_cfg["enabled"] = True
    backend_cfg["url"] = "http://127.0.0.1:8001/api/v1/telemetry"

    output_config.parent.mkdir(parents=True, exist_ok=True)
    with output_config.open("w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, sort_keys=False)

    profile = {
        "target_url": args.target_url.rstrip("/"),
        "proxy_url": args.proxy_url.rstrip("/"),
        "model": args.model,
        "upstream_bearer": args.upstream_key.strip(),
        "config_path": str(output_config),
    }
    profile_file.parent.mkdir(parents=True, exist_ok=True)
    with profile_file.open("w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)

    print(f"[OK] Demo config written: {output_config}")
    print(f"[OK] Demo profile written: {profile_file}")
    print(f"[INFO] Proxy will forward to: {profile['target_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
