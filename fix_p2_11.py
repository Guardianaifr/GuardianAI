import re

with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_fwd = '''        # Prepare headers
        fwd_headers = {key: value for (key, value) in request.headers if key != 'Host'}
        
        # SECURITY FEATURE: Upstream Key Injection
        upstream_key = self.config.get('proxy', {}).get('upstream_key')
        if upstream_key:
            fwd_headers['Authorization'] = f"Bearer {upstream_key}"
            if "anthropic" in self.target_url:
                fwd_headers['x-api-key'] = upstream_key

        try:
            is_stream = data and data.get("stream") is True
            resp = requests.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                timeout=30,  # Prevent indefinite hangs (Increased for stability)
                stream=is_stream,
                proxies={"http": None, "https": None} # Bypass system proxies
            )'''

new_fwd = '''        # Prepare headers
        # Strip Host, X-Guardian-Token (internal auth), and any other Guardian-specific headers
        fwd_headers = {
            key: value for (key, value) in request.headers 
            if key.lower() not in ('host', 'x-guardian-token')
        }
        
        # SECURITY FEATURE: Upstream Key Injection
        upstream_key = self.config.get('proxy', {}).get('upstream_key')
        if upstream_key:
            fwd_headers['Authorization'] = f"Bearer {upstream_key}"
            if "anthropic" in self.target_url:
                fwd_headers['x-api-key'] = upstream_key

        try:
            is_stream = data and data.get("stream") is True
            resp = requests.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                data=request.get_data(),
                # Cookies are stripped. Upstream LLM APIs (OpenAI, Anthropic) do not use cookies.
                # Forwarding them poses a risk of leaking unrelated client session credentials.
                cookies=None,
                allow_redirects=False,
                timeout=30,  # Prevent indefinite hangs (Increased for stability)
                stream=is_stream,
                proxies={"http": None, "https": None} # Bypass system proxies
            )'''

content = content.replace(old_fwd, new_fwd)

with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
