with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_comment = '''# Note: This is separate from backend/rbac.py and the auth proxy layer, which
# define a granular multi-tenant role matrix (admin, analyst, tenant_admin, read_only)
# for proxy and tenant scoping. Uses unified stateless JWT + Basic auth natively built in main.py.'''

new_comment = '''# Note: This set represents the single active authorization layer for the backend.
# The legacy auth proxy layer in backend/auth.py and backend/rbac.py has been stripped
# of its runtime access gates and now serves purely as cryptographic utilities
# (password hashing and JWT decode primitives).'''

content = content.replace(old_comment, new_comment)

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
