import re

with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_jwt_secret = '''_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning(
        "GUARDIAN_JWT_SECRET not set. Using ephemeral key — tokens will be "
        "invalidated on restart. NOT suitable for production."
    )'''

new_jwt_secret = '''_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    import sys
    if os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        _logger.error("CRITICAL SECURITY ERROR: GUARDIAN_JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
    
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning(
        "GUARDIAN_JWT_SECRET not set. Using ephemeral key — tokens will be "
        "invalidated on restart. NOT suitable for production."
    )'''

# Also fix the weird em-dash from log
content = content.replace("ephemeral key — tokens", "ephemeral key - tokens")
old_jwt_secret = old_jwt_secret.replace("ephemeral key — tokens", "ephemeral key - tokens")
new_jwt_secret = new_jwt_secret.replace("ephemeral key — tokens", "ephemeral key - tokens")

# Actually let's just do a string replace since python source might have the exact unicode char
content = content.replace(
'''_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning(
        "GUARDIAN_JWT_SECRET not set. Using ephemeral key — tokens will be "
        "invalidated on restart. NOT suitable for production."
    )''',
'''_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    import sys
    if os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        _logger.error("CRITICAL SECURITY ERROR: GUARDIAN_JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
        
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning(
        "GUARDIAN_JWT_SECRET not set. Using ephemeral key — tokens will be "
        "invalidated on restart. NOT suitable for production."
    )'''
)

# wait some terminals render the em dash differently, I'll regex it to be safe
content = re.sub(
    r'_raw_jwt_secret = os\.getenv\("GUARDIAN_JWT_SECRET", ""\)\.strip\(\)\nif _raw_jwt_secret:\n    JWT_SECRET = _raw_jwt_secret\nelse:\n    JWT_SECRET = secrets\.token_urlsafe\(64\)\n    _logger\.warning\([^)]+\)',
    r'''_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    import sys
    if os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        _logger.error("CRITICAL SECURITY ERROR: GUARDIAN_JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
        
    JWT_SECRET = secrets.token_urlsafe(64)
    _logger.warning("GUARDIAN_JWT_SECRET not set. Using ephemeral key. NOT suitable for production.")''',
    content
)

with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)
