from security.idp_revocation import build_subject
from security.idp_revocation import IdpRevocationClient


def test_build_subject_extracts_jwt_claims():
    jwt = "aaa.eyJzdWIiOiJ1c2VyLTEyMyIsImp0aSI6InRva2VuLTQ1NiJ9.ccc"
    subject = build_subject("sess-1", jwt, include_raw_jwt=False)
    assert subject.session_id == "sess-1"
    assert subject.jwt_sub == "user-123"
    assert subject.jwt_jti == "token-456"
    assert subject.token_hash is not None
    assert subject.raw_jwt is None


def test_okta_adapter_contract_shape(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

    def _fake_post(url, json, headers, timeout):  # noqa: A002
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr("security.idp_revocation.requests.post", _fake_post)
    client = IdpRevocationClient(
        {
            "enabled": True,
            "provider": "okta",
            "okta_revoke_url": "https://okta.example/revoke",
            "token": "okta-api-token",
            "timeout_seconds": 3,
        }
    )
    subject = build_subject("sess-1", "aaa.eyJzdWIiOiJ1LTEiLCJqdGkiOiJqdGktMSJ9.ccc")
    assert client.revoke(subject, reason="security_test") is True
    assert captured["url"] == "https://okta.example/revoke"
    assert captured["headers"]["Authorization"].startswith("SSWS ")
    assert captured["json"]["event_type"] == "guardian.session.revoke"
    assert captured["json"]["subject"]["sub"] == "u-1"


def test_auth0_adapter_contract_shape(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

    def _fake_post(url, json, headers, timeout):  # noqa: A002
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr("security.idp_revocation.requests.post", _fake_post)
    client = IdpRevocationClient(
        {
            "enabled": True,
            "provider": "auth0",
            "auth0_revoke_url": "https://auth0.example/revoke",
            "token": "auth0-token",
        }
    )
    subject = build_subject("sess-2", "aaa.eyJzdWIiOiJ1LTIiLCJqdGkiOiJqdGktMiJ9.ccc")
    assert client.revoke(subject, reason="security_test") is True
    assert captured["url"] == "https://auth0.example/revoke"
    assert captured["json"]["sub"] == "u-2"
    assert captured["json"]["jti"] == "jti-2"


def test_azure_adapter_contract_shape(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

    def _fake_post(url, json, headers, timeout):  # noqa: A002
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr("security.idp_revocation.requests.post", _fake_post)
    client = IdpRevocationClient(
        {
            "enabled": True,
            "provider": "azuread",
            "azure_revoke_url": "https://graph.example/revoke",
            "token": "azure-token",
        }
    )
    subject = build_subject("sess-3", "aaa.eyJzdWIiOiJ1LTMiLCJqdGkiOiJqdGktMyJ9.ccc")
    assert client.revoke(subject, reason="security_test") is True
    assert captured["url"] == "https://graph.example/revoke"
    assert captured["json"]["userId"] == "u-3"
    assert captured["json"]["tokenId"] == "jti-3"
