with open('backend/auth.py', 'r', encoding='utf-8') as f:
    auth_content = f.read()

start_auth = auth_content.find("class AuthManager:")
if start_auth != -1:
    auth_content = auth_content[:start_auth]
    with open('backend/auth.py', 'w', encoding='utf-8') as f:
        f.write(auth_content)
        
with open('backend/rbac.py', 'r', encoding='utf-8') as f:
    rbac_content = f.read()

start_rbac = rbac_content.find("def get_current_user_from_token")
if start_rbac != -1:
    rbac_content = rbac_content[:start_rbac]
    with open('backend/rbac.py', 'w', encoding='utf-8') as f:
        f.write(rbac_content)
