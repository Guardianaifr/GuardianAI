import re

with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_validate = '''def _validate_basic(credentials: HTTPBasicCredentials) -> str:
    user_config = _auth_users.get(credentials.username)
    
    # Anti-enumeration: always verify a hash to equalize timing.
    # If the user doesn't exist, we verify against the admin's hash (or any valid hash).
    stored = user_config["password"] if user_config else list(_auth_users.values())[0]["password"]
    
    ok = verify_password(credentials.password, stored)
    
    if not user_config or not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username'''

content = re.sub(r'def _validate_basic\(credentials: HTTPBasicCredentials\) -> str:.*?return credentials\.username', new_validate, content, flags=re.DOTALL)

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
