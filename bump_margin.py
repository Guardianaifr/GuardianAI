with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('margin = 500', 'margin = 2048')

with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
