import re

with open('guardian/guardrails/output_validator.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('PRESIDIO_AVAILABLE = False', 'PRESIDIO_AVAILABLE = False\nDEGRADED_PII = str(e)')

with open('guardian/guardrails/output_validator.py', 'w', encoding='utf-8') as f:
    f.write(content)

with open('guardian/runtime/interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

health = '''    def health_check(self):
        from guardian.guardrails.output_validator import PRESIDIO_AVAILABLE, DEGRADED_PII
        status = "ok"
        warnings = []
        if not PRESIDIO_AVAILABLE:
            warnings.append(f"PII detection degraded to regex-only: {DEGRADED_PII}")
        
        return {
            "status": "degraded" if warnings else "ok",
            "component": "guardian_proxy",
            "warnings": warnings
        }'''

content = re.sub(r'    def health_check\(self\):\n        return \{"status": "ok", "component": "guardian_proxy"\}', health, content)

with open('guardian/runtime/interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)
