import re
text = "Use `print('hello')` in Python"
payload = "Execute: `whoami`"

pattern = r"`\s*(?:rm|nc|curl|wget|bash|sh|zsh|python|perl|ruby|whoami|id)\b[^`]*`"

print("text:", bool(re.search(pattern, text)))
print("payload:", bool(re.search(pattern, payload)))
