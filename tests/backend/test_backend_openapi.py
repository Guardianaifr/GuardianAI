from fastapi.testclient import TestClient

import backend.main as backend_main


def test_openapi_includes_hardening_endpoint_schemas_and_examples():
    client = TestClient(backend_main.app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    spec = response.json()

    token_post = spec["paths"]["/api/v1/auth/token"]["post"]
    token_schema_ref = token_post["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    token_schema_name = token_schema_ref.split("/")[-1]
    token_schema = spec["components"]["schemas"][token_schema_name]
    assert "role" in token_schema["properties"]
    assert "example" in token_post["responses"]["200"]["content"]["application/json"]
    assert "429" in token_post["responses"]
    assert "example" in token_post["responses"]["429"]["content"]["application/json"]

    revoke_post = spec["paths"]["/api/v1/auth/revoke"]["post"]
    assert "example" in revoke_post["responses"]["200"]["content"]["application/json"]
    revocations_get = spec["paths"]["/api/v1/auth/revocations"]["get"]
    assert "example" in revocations_get["responses"]["200"]["content"]["application/json"]
    revocations_prune_post = spec["paths"]["/api/v1/auth/revocations/prune"]["post"]
    assert "example" in revocations_prune_post["responses"]["200"]["content"]["application/json"]
    lockouts_get = spec["paths"]["/api/v1/auth/lockouts"]["get"]
    assert "example" in lockouts_get["responses"]["200"]["content"]["application/json"]
    lockouts_clear_post = spec["paths"]["/api/v1/auth/lockouts/clear"]["post"]
    assert "example" in lockouts_clear_post["responses"]["200"]["content"]["application/json"]
    sessions_get = spec["paths"]["/api/v1/auth/sessions"]["get"]
    assert "example" in sessions_get["responses"]["200"]["content"]["application/json"]
    sessions_revoke_user_post = spec["paths"]["/api/v1/auth/sessions/revoke-user"]["post"]
    assert "example" in sessions_revoke_user_post["responses"]["200"]["content"]["application/json"]
    sessions_revoke_jti_post = spec["paths"]["/api/v1/auth/sessions/revoke-jti"]["post"]
    assert "example" in sessions_revoke_jti_post["responses"]["200"]["content"]["application/json"]
    whoami_get = spec["paths"]["/api/v1/auth/whoami"]["get"]
    assert "example" in whoami_get["responses"]["200"]["content"]["application/json"]

    telemetry_examples = (
        spec["paths"]["/api/v1/telemetry"]["post"]["requestBody"]["content"]["application/json"]["examples"]
    )
    assert "admin_action" in telemetry_examples

    api_keys_get = spec["paths"]["/api/v1/api-keys"]["get"]
    assert "example" in api_keys_get["responses"]["200"]["content"]["application/json"]

    api_key_revoke_post = spec["paths"]["/api/v1/api-keys/{key_id}/revoke"]["post"]
    assert "example" in api_key_revoke_post["responses"]["200"]["content"]["application/json"]

    api_key_rotate_post = spec["paths"]["/api/v1/api-keys/{key_id}/rotate"]["post"]
    assert "example" in api_key_rotate_post["responses"]["200"]["content"]["application/json"]

    verify_schema_ref = (
        spec["paths"]["/api/v1/audit-log/verify"]["get"]["responses"]["200"]["content"]["application/json"]["schema"][
            "$ref"
        ]
    )
    verify_schema_name = verify_schema_ref.split("/")[-1]
    verify_schema = spec["components"]["schemas"][verify_schema_name]
    assert "ok" in verify_schema["properties"]
    assert "entries" in verify_schema["properties"]
    assert "example" in spec["paths"]["/api/v1/audit-log"]["get"]["responses"]["200"]["content"]["application/json"]
    assert (
        "example"
        in spec["paths"]["/api/v1/audit-log/summary"]["get"]["responses"]["200"]["content"]["application/json"]
    )
    assert (
        "example"
        in spec["paths"]["/api/v1/audit-log/failures"]["get"]["responses"]["200"]["content"]["application/json"]
    )
    assert (
        "example"
        in spec["paths"]["/api/v1/audit-log/retry-failures"]["post"]["responses"]["200"]["content"]["application/json"]
    )

    health_get = spec["paths"]["/health"]["get"]
    assert "example" in health_get["responses"]["200"]["content"]["application/json"]
    assert "503" in health_get["responses"]
    assert "example" in health_get["responses"]["503"]["content"]["application/json"]

    metrics_get = spec["paths"]["/metrics"]["get"]
    assert "text/plain" in metrics_get["responses"]["200"]["content"]

    compliance_get = spec["paths"]["/api/v1/compliance/report"]["get"]
    assert "example" in compliance_get["responses"]["200"]["content"]["application/json"]
    rbac_policy_get = spec["paths"]["/api/v1/rbac/policy"]["get"]
    assert "example" in rbac_policy_get["responses"]["200"]["content"]["application/json"]
