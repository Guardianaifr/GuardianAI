from __future__ import annotations

import guardianctl


def test_ensure_one_click_env_generates_required_values():
    env, generated = guardianctl.ensure_one_click_env({})

    assert env["GUARDIAN_ADMIN_USER"] == "admin"
    assert env["GUARDIAN_SERVICE_ID"] == "guardian-proxy"
    assert env["GUARDIAN_ADMIN_PASS"]
    assert env["GUARDIAN_BACKEND_TOKEN"]
    assert env["GUARDIAN_SERVICE_AUTH_TOKEN"]
    assert env["GUARDIAN_ADMIN_BYPASS_TOKEN"]
    assert set(generated.keys()) >= {
        "GUARDIAN_ADMIN_PASS",
        "GUARDIAN_BACKEND_TOKEN",
        "GUARDIAN_SERVICE_AUTH_TOKEN",
        "GUARDIAN_ADMIN_BYPASS_TOKEN",
    }


def test_ensure_one_click_env_preserves_existing_secrets():
    base = {
        "GUARDIAN_ADMIN_USER": "ops",
        "GUARDIAN_ADMIN_PASS": "admin-pass",
        "GUARDIAN_BACKEND_TOKEN": "backend-token",
        "GUARDIAN_SERVICE_AUTH_TOKEN": "service-token",
        "GUARDIAN_ADMIN_BYPASS_TOKEN": "bypass-token",
        "GUARDIAN_SERVICE_ID": "proxy-x",
    }
    env, generated = guardianctl.ensure_one_click_env(base)

    assert env == base
    assert generated == {}


def test_build_one_click_config_sets_full_feature_profile(monkeypatch):
    monkeypatch.setenv("GUARDIAN_BACKEND_TOKEN", "backend")
    monkeypatch.setenv("GUARDIAN_SERVICE_AUTH_TOKEN", "service")
    monkeypatch.setenv("GUARDIAN_SERVICE_ID", "proxy-a")
    monkeypatch.setenv("GUARDIAN_WATERMARK_KEY", "wmk")

    config = guardianctl.build_one_click_config(
        target_url="http://127.0.0.1:9000",
        proxy_port=8181,
        backend_port=8101,
        admin_bypass_token="bypass",
    )

    assert config["proxy"]["listen_port"] == 8181
    assert config["proxy"]["target_url"] == "http://127.0.0.1:9000"
    assert config["backend"]["url"] == "http://127.0.0.1:8101/api/v1/telemetry"
    assert config["backend"]["token"] == "backend"
    assert config["backend"]["service_auth_token"] == "service"
    assert config["backend"]["service_id"] == "proxy-a"
    assert config["security_policies"]["admin_token"] == "bypass"
    assert config["agentic_security"]["enabled"] is True
    assert config["rag_security"]["enabled"] is True
    assert config["multimodal_security"]["enabled"] is True
    assert config["output_assurance"]["enabled"] is True
    assert config["output_watermark"]["enabled"] is True
    assert config["output_watermark"]["key"] == "wmk"
    assert config["threat_feed"]["enabled"] is False
    assert config["threat_feed"]["url"] == ""


def test_build_one_click_config_enables_threat_feed_when_url_present(monkeypatch):
    monkeypatch.setenv("GUARDIAN_THREAT_FEED_URL", "https://example.com/feed.yaml")

    config = guardianctl.build_one_click_config(
        target_url="http://127.0.0.1:9000",
        proxy_port=8181,
        backend_port=8101,
        admin_bypass_token="bypass",
    )

    assert config["threat_feed"]["enabled"] is True
    assert config["threat_feed"]["url"] == "https://example.com/feed.yaml"
