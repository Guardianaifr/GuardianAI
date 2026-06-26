from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth


class _FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("No JSON payload")
        return self._json_data


def test_scanner_discovers_chat_endpoint_from_project_page(monkeypatch):
    html = """
    <html>
      <head><title>Monad Agent Portal</title></head>
      <body>
        <script>
          const provider = "OpenAI";
          const sdk = "ethers";
          fetch('/api/v1/chat/completions', { method: 'POST' });
        </script>
      </body>
    </html>
    """

    def fake_get(url, **kwargs):
        assert url == "https://project.example"
        return _FakeResponse(
            status_code=200,
            text=html,
            headers={
                "content-type": "text/html; charset=utf-8",
                "server": "cloudflare",
                "x-powered-by": "Next.js",
            },
        )

    def fake_options(url, **kwargs):
        return _FakeResponse(status_code=204, headers={"allow": "POST, OPTIONS"})

    monkeypatch.setattr("guardian.audit.crypto_scanner.requests.get", fake_get)
    monkeypatch.setattr("guardian.audit.crypto_scanner.requests.options", fake_options)

    scanner = CryptoAuditScanner("project.example", depth=ScanDepth.QUICK)
    scanner.discover_target()

    assert scanner.target_url == "https://project.example"
    assert scanner.primary_endpoint == "https://project.example/api/v1/chat/completions"
    assert scanner.crawl_summary["selected_endpoint"] == "https://project.example/api/v1/chat/completions"
    assert scanner.detected_tech["llm_provider"] == "OpenAI"
    assert scanner.detected_tech["web3_sdk"] == "ethers.js"
    assert scanner.detected_tech["app_runtime"] == "Next.js"
    assert scanner.discovered_endpoints
    assert scanner.discovered_endpoints[0].url == "https://project.example/api/v1/chat/completions"


def test_run_scan_uses_discovered_endpoint_for_project_url(monkeypatch):
    html = """
    <html>
      <body>
        <script>
          fetch('/api/v1/chat/completions', { method: 'POST' });
        </script>
      </body>
    </html>
    """

    def fake_get(url, **kwargs):
        return _FakeResponse(
            status_code=200,
            text=html,
            headers={"content-type": "text/html; charset=utf-8"},
        )

    def fake_options(url, **kwargs):
        return _FakeResponse(status_code=204, headers={"allow": "POST, OPTIONS"})

    def fake_post(url, **kwargs):
        assert url == "https://project.example/api/v1/chat/completions"
        return _FakeResponse(
            status_code=200,
            json_data={"choices": [{"message": {"content": "I cannot help with that request."}}]},
        )

    monkeypatch.setattr("guardian.audit.crypto_scanner.requests.get", fake_get)
    monkeypatch.setattr("guardian.audit.crypto_scanner.requests.options", fake_options)
    monkeypatch.setattr("guardian.audit.crypto_scanner.requests.post", fake_post)

    scanner = CryptoAuditScanner("https://project.example", target_name="Project Example", depth=ScanDepth.QUICK)
    result = scanner.run_scan()

    assert result.primary_endpoint == "https://project.example/api/v1/chat/completions"
    assert result.discovered_endpoints
    assert result.total_vectors > 0
    assert result.protected_count == result.total_vectors
    assert result.vulnerabilities_found == 0
    assert result.crawl_summary["selected_endpoint"] == "https://project.example/api/v1/chat/completions"
