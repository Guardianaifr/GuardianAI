import re

with open('guardian/guardrails/output_validator.py', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('''except Exception as e:
    logger.warning(f"Microsoft Presidio not found or incompatible in current runtime. Falling back to basic regex. Error: {e}")
    PRESIDIO_AVAILABLE = False
DEGRADED_PII = str(e)''', '''except Exception as e:
    logger.warning(f"Microsoft Presidio not found or incompatible in current runtime. Falling back to basic regex. Error: {e}")
    PRESIDIO_AVAILABLE = False
    DEGRADED_PII = str(e)''')

with open('guardian/guardrails/output_validator.py', 'w', encoding='utf-8') as f:
    f.write(content)
