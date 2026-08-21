import re

with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_debug = '''        # DEBUG INFO UPDATE
        self._update_debug_info({
            "path": path,
            "tenant_id": tenant_id,
            "method": request.method,
            "content_type": request.content_type,
            "raw_len": raw_len,
            "data_parsed": bool(data),
            "data_keys": list(data.keys()) if isinstance(data, dict) else str(type(data)),
            "prompt_extracted": prompt,
            "headers": dict(request.headers)
        })'''

new_debug = '''        # DEBUG INFO UPDATE
        # P2-16: Redact sensitive headers before storing in memory
        safe_headers = dict(request.headers)
        for sensitive_key in ['Authorization', 'X-Guardian-Token', 'x-api-key']:
            for header_key in list(safe_headers.keys()):
                if header_key.lower() == sensitive_key.lower():
                    val = safe_headers[header_key]
                    if val.lower().startswith('bearer '):
                        safe_headers[header_key] = val[:10] + '***' + val[-4:]
                    else:
                        safe_headers[header_key] = '***REDACTED***'

        self._update_debug_info({
            "path": path,
            "tenant_id": tenant_id,
            "method": request.method,
            "content_type": request.content_type,
            "raw_len": raw_len,
            "data_parsed": bool(data),
            "data_keys": list(data.keys()) if isinstance(data, dict) else str(type(data)),
            "prompt_extracted": prompt[:100] + '...[REDACTED]' if prompt and len(prompt) > 100 else prompt,
            "headers": safe_headers
        })'''

content = content.replace(old_debug, new_debug)

old_route = '''    def debug_info(self):'''
new_route = '''    def debug_info(self):
        # P2-16: Feature-flag off in production
        if os.getenv("GUARDIAN_ENV") != "development":
            return Response("Forbidden: Debug route disabled in production.", status=403)
'''

content = content.replace(old_route, new_route)

with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
