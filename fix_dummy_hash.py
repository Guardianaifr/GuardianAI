import re

with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

# We can pre-compute a valid argon2id hash at module load.
# Actually, since it's just a dummy, it's perfectly fine to hardcode a VALID hash string.
old_logic = '''    # Anti-enumeration: always verify a hash to equalize timing.
    # If the user doesn't exist, we verify against a static dummy hash to avoid relying on dictionary state.
    # This is a valid Argon2 hash for the word "dummy".
    DUMMY_HASH = "$argon2id$v=19$m=65536,t=7,p=4$4/R9QOq4jO/5y2J9P0N1qQ$t/Z8Y3W8y9w2u3O3R4+w0w0Q2Q0V2Z4V2Z4V2Z4V2Z4"
    stored = user_config["password"] if user_config else DUMMY_HASH'''

new_logic = '''    # Anti-enumeration: always verify a hash to equalize timing.
    # If the user doesn't exist, we verify against a static, genuinely valid dummy hash.
    # Generated via hash_password("dummy") to ensure valid base64 and checksum.
    DUMMY_HASH = "$argon2id$v=19$m=65536,t=7,p=4$KUGcP8geNdGLxEzipJtshQ$BiFNhl23xD9jhkM4YXPtzmfc1AR6XL1n6BV4zvcj5Ak"
    stored = user_config["password"] if user_config else DUMMY_HASH'''

content = content.replace(old_logic, new_logic)

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
