import re

with open('guardian/guardrails/output_validator.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('PRESIDIO_AVAILABLE = True', 'PRESIDIO_AVAILABLE = True\n    DEGRADED_PII = None')

with open('guardian/guardrails/output_validator.py', 'w', encoding='utf-8') as f:
    f.write(content)
