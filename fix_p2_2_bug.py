with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace("yield 'data: {\"error\": \"Forbidden: Potential data leak blocked by GuardianAI.\"}\\n\\n'\n                                    break", "yield 'data: {\"error\": \"Forbidden: Potential data leak blocked by GuardianAI.\"}\\n\\n'\n                                    return")

with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
