import hashlib

def hash_token(t):
    return hashlib.sha256(str(t).encode()).hexdigest()[:8] if t else 'None'

with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix P1-1
old_log = 'logger.warning(f"ADMIN FAIL: Invalid or missing token from {request.remote_addr}. ConfigToken={admin_token}, ReqToken={request_token}")'
new_log = 'logger.warning(f"ADMIN FAIL: Invalid or missing token from {request.remote_addr}. ConfigTokenHash={hashlib.sha256(str(admin_token).encode()).hexdigest()[:8] if admin_token else \'None\'}, ReqTokenHash={hashlib.sha256(str(request_token).encode()).hexdigest()[:8] if request_token else \'None\'}")'

content = content.replace(old_log, new_log)
with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
