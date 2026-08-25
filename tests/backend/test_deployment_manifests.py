from pathlib import Path

import yaml


def _load_yaml_documents(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def test_prometheus_assets_include_scrape_and_alerts():
    repo_root = Path(__file__).resolve().parents[2]
    scrape_cfg = repo_root / "deploy" / "prometheus" / "scrape-config.yaml"
    alert_rules = repo_root / "deploy" / "prometheus" / "guardian-alert-rules.yaml"

    scrape_doc = _load_yaml_documents(scrape_cfg)[0]
    rules_doc = _load_yaml_documents(alert_rules)[0]

    jobs = scrape_doc.get("scrape_configs", [])
    job_names = {job.get("job_name") for job in jobs}
    assert "guardian-backend" in job_names

    groups = rules_doc.get("groups", [])
    group_names = {group.get("name") for group in groups}
    assert "guardian-backend-alerts" in group_names
