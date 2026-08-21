import re

for file in ['tests/security/test_adversarial.py', 'tests/stress/test_stress.py']:
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Remove AuthManager import
    content = content.replace('AuthManager, ', '')
    content = content.replace('AuthManager', '')
    
    with open(file, 'w', encoding='utf-8') as f:
        f.write(content)
