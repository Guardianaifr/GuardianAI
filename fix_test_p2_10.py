import re

with open('contracts/test/test_p2_10_vault.ts', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('expect(err).to.include("ReentrancyGuard: reentrant call");', 'expect(err).to.include("ReentrancyGuardReentrantCall()");')

with open('contracts/test/test_p2_10_vault.ts', 'w', encoding='utf-8') as f:
    f.write(content)
