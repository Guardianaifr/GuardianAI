import requests

try:
    resp = requests.post(
        "http://127.0.0.1:8082/test_route",
        headers={"X-Guardian-Token": "secret_guardian_token", "User-Agent": "test-agent"},
        cookies={"session_id": "secret_cookie"},
        json={"message": "hello"},
        timeout=2
    )
    print(resp.json())
except Exception as e:
    print("Error:", e)
