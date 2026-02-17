import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def test_jwt_revoke_blocks_reused_token(tmp_path, monkeypatch):
    db_path = tmp_path / "jwt_revoke.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    client = TestClient(backend_main.app)

    token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers())
    assert token_res.status_code == 200
    bearer_token = token_res.json()["access_token"]
    bearer_headers = {"Authorization": f"Bearer {bearer_token}"}

    before_revoke = client.get("/api/v1/analytics", headers=bearer_headers)
    assert before_revoke.status_code == 200

    revoke_res = client.post("/api/v1/auth/revoke", headers=bearer_headers)
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"

    after_revoke = client.get("/api/v1/analytics", headers=bearer_headers)
    assert after_revoke.status_code == 401
    assert "revoked" in after_revoke.json()["detail"].lower()


def test_revoke_requires_bearer_token():
    client = TestClient(backend_main.app)
    response = client.post("/api/v1/auth/revoke")
    assert response.status_code == 401
