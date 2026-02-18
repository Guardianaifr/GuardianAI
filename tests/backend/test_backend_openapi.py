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

    telemetry_examples = (
        spec["paths"]["/api/v1/telemetry"]["post"]["requestBody"]["content"]["application/json"]["examples"]
    )
    assert "admin_action" in telemetry_examples

    verify_schema_ref = (
        spec["paths"]["/api/v1/audit-log/verify"]["get"]["responses"]["200"]["content"]["application/json"]["schema"][
            "$ref"
        ]
    )
    verify_schema_name = verify_schema_ref.split("/")[-1]
    verify_schema = spec["components"]["schemas"][verify_schema_name]
    assert "ok" in verify_schema["properties"]
    assert "entries" in verify_schema["properties"]

    health_get = spec["paths"]["/health"]["get"]
    assert "503" in health_get["responses"]
