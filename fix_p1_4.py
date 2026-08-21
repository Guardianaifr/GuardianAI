with open('backend/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('Both systems are maintained for dual-layer security.', 'Uses unified stateless JWT + Basic auth natively built in main.py.')

with open('backend/main.py', 'w', encoding='utf-8') as f:
    f.write(content)
