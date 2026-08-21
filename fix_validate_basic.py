import re

with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_validate = '''def _validate_basic(credentials: HTTPBasicCredentials) -> str:
    user_config = _auth_users.get(credentials.username)
    if not user_config:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    stored = user_config["password"]
    # Support both hashed (salt) and plain-text passwords.
    # Plain-text is used in tests; production uses hash_password() output.
    if "$" in stored:
        ok = verify_password(credentials.password, stored)
    else:
        import hmac as _hmac
        ok = _hmac.compare_digest(credentials.password, stored)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )'''

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
        )'''

if old_validate in content:
    content = content.replace(old_validate, new_validate)
else:
    print("WARNING: Could not find old_validate block!")

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
