import re

with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_aud = '''    # 6. Check audience (aud) if present — must match JWT_AUDIENCE env if set
    token_aud = payload.get("aud")
    expected_aud = os.getenv("GUARDIAN_JWT_AUDIENCE", "").strip()
    if expected_aud and token_aud:
        # Support single string or list of audiences
        if isinstance(token_aud, str):
            if token_aud != expected_aud:
                raise ValueError("Invalid token audience")
        elif isinstance(token_aud, list):
            if expected_aud not in token_aud:
                raise ValueError("Invalid token audience")'''

new_aud = '''    # 6. Check audience (aud) — must match JWT_AUDIENCE env if set
    token_aud = payload.get("aud")
    expected_aud = os.getenv("GUARDIAN_JWT_AUDIENCE", "").strip()
    if expected_aud:
        if not token_aud:
            raise ValueError("Missing token audience")
        # Support single string or list of audiences
        if isinstance(token_aud, str):
            if token_aud != expected_aud:
                raise ValueError("Invalid token audience")
        elif isinstance(token_aud, list):
            if expected_aud not in token_aud:
                raise ValueError("Invalid token audience")'''

# Need to handle encoding characters like the em-dash in comments
content = content.replace('    # 6. Check audience (aud) if present', '    # 6. Check audience (aud)')
content = re.sub(r'    token_aud = payload\.get\("aud"\)\n    expected_aud = os\.getenv\("GUARDIAN_JWT_AUDIENCE", ""\)\.strip\(\)\n    if expected_aud and token_aud:', '    token_aud = payload.get("aud")\n    expected_aud = os.getenv("GUARDIAN_JWT_AUDIENCE", "").strip()\n    if expected_aud:\n        if not token_aud:\n            raise ValueError("Missing token audience")', content)

with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)
