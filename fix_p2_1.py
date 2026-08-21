with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_attestation = 'AGENTIC_ATTESTATION_SECRET = os.getenv("GUARDIAN_AGENTIC_ATTESTATION_SECRET", "default_agentic_key_change_me_in_prod").strip() or "default_agentic_key_change_me_in_prod"'

new_attestation = '''_raw_agentic_secret = os.getenv("GUARDIAN_AGENTIC_ATTESTATION_SECRET", "").strip()
if _raw_agentic_secret:
    AGENTIC_ATTESTATION_SECRET = _raw_agentic_secret
else:
    AGENTIC_ATTESTATION_SECRET = secrets.token_urlsafe(64)
    logger.warning("GUARDIAN_AGENTIC_ATTESTATION_SECRET not set. Using ephemeral key. NOT suitable for production.")'''

content = content.replace(old_attestation, new_attestation)

prod_check_old = '''    if not _raw_jwt_secret:
        logger.error("CRITICAL SECURITY ERROR: JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)'''

prod_check_new = '''    if not _raw_jwt_secret:
        logger.error("CRITICAL SECURITY ERROR: JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
    if not _raw_agentic_secret:
        logger.error("CRITICAL SECURITY ERROR: GUARDIAN_AGENTIC_ATTESTATION_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)'''

content = content.replace(prod_check_old, prod_check_new)

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
