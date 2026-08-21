with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_cond = 'if admin_token and request_token == admin_token:'
new_cond = 'if admin_token and secrets.compare_digest(request_token or "", admin_token):'

content = content.replace(old_cond, new_cond)
with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
