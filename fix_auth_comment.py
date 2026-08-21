with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

old_comment = '''# ---------------------------------------------------------------------------
# Auth Manager
# ---------------------------------------------------------------------------'''

content = content.replace(old_comment, "")

with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content.rstrip() + "\n")
