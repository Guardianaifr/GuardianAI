import sys, os, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# 1. Check API key endpoints exist in backend/main.py
with open('backend/main.py', 'r', encoding='utf-8') as f:
    main_src = f.read()

checks = {
    'API Key Create endpoint':        '/api/v1/api-keys' in main_src and 'create_api_key' in main_src,
    'API Key List endpoint':          'list_api_keys' in main_src,
    'API Key Revoke endpoint':        'revoke_api_key' in main_src,
    'API Key Rotate endpoint':        'rotate_api_key' in main_src,
    'TELEMETRY_REQUIRE_API_KEY var':  'TELEMETRY_REQUIRE_API_KEY' in main_src,
    'AUTH_RATE_LIMIT_PER_MIN var':    'AUTH_RATE_LIMIT_PER_MIN' in main_src,
    '_rate_limit_state var':          '_rate_limit_state' in main_src,
    'Auth token endpoint':            '/api/v1/auth/token' in main_src and 'auth_token' in main_src,
    '_check_auth_rate_limit fn':      '_check_auth_rate_limit' in main_src,
    '_check_api_key_auth fn':         '_check_api_key_auth' in main_src,
    'api_keys table in init_db':      'CREATE TABLE IF NOT EXISTS api_keys' in main_src,
    'API key check in telemetry':     '_check_api_key_auth(request)' in main_src,
}

# 2. Check proxy auth module
with open('guardian/proxy/auth_proxy.py', 'r', encoding='utf-8') as f:
    proxy_src = f.read()
proxy_checks = {
    'JWT strip (build_proxy_headers)':      'build_proxy_headers' in proxy_src,
    'Model allowlist (check_model_allowed)':'check_model_allowed' in proxy_src,
    'Request translation':                   'translate_request' in proxy_src,
    'TokenBucketRateLimiter':               'TokenBucketRateLimiter' in proxy_src,
    '5 backends defined':                    all(b in proxy_src for b in ['ollama','vllm','localai','llamacpp','openai']),
}

# 3. Check test files exist
test_files = {
    'test_auth_heavy.py':               os.path.exists('tools/test_auth_heavy.py'),
    'test_auth_proxy.py':               os.path.exists('tests/proxy/test_auth_proxy.py'),
    'test_unauthorized_access.py':      os.path.exists('tests/backend/test_unauthorized_access.py'),
    'test_backend_api_keys.py':         os.path.exists('tests/backend/test_backend_api_keys.py'),
    'test_backend_auth_rate_limit.py':  os.path.exists('tests/backend/test_backend_auth_rate_limit.py'),
}

# 4. Check evidence artifact
evidence = {
    'auth_heavy.json artifact':         os.path.exists('artifacts/evidence/auth_heavy.json'),
}

# 5. Check test counts in evidence file
if os.path.exists('artifacts/evidence/auth_heavy.json'):
    with open('artifacts/evidence/auth_heavy.json') as f:
        data = json.load(f)
    evidence['auth_heavy: all passed'] = data.get('passed') == data.get('total')
    evidence[f"auth_heavy: {data.get('passed')}/{data.get('total')} tests"] = True

all_ok = True
print('=' * 60)
print('  FEATURE #12 CAPABILITY VERIFICATION')
print('=' * 60)

for cat, items in [
    ('Backend Code', checks),
    ('Proxy Code', proxy_checks),
    ('Test Files', test_files),
    ('Evidence', evidence),
]:
    print(f'\n  [{cat}]')
    for name, result in items.items():
        status = 'OK' if result else 'MISSING'
        if not result:
            all_ok = False
        print(f'    [{status}] {name}')

verdict = 'ALL OK - 100% verified' if all_ok else 'GAPS FOUND'
print(f'\n  VERDICT: {verdict}')
print('=' * 60)
sys.exit(0 if all_ok else 1)
