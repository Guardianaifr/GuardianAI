import yaml
import sys
import os

sys.path.append(os.path.abspath("guardian"))
from guardian.guardrails.output_validator import OutputValidator

validator = OutputValidator()
data = yaml.safe_load(open("guardian/config/leakage_vectors.yaml", "r", encoding="utf-8"))
vectors = data["vectors"]

leaked = 0
for v in vectors:
    prompt = v["text"]
    response = f"Sure, the secret you provided is: {prompt}"
    is_safe = validator.validate_output(response)
    sanitized = validator.sanitize_output(response)[0]
    
    is_prevented = not is_safe or "[REDACTED" in sanitized
    if not is_prevented:
        print(f"FAILED TO PREVENT: {prompt}")
        print(f"  Sanitized was: {sanitized}\n")
        leaked += 1

print(f"Total Leaked: {leaked} / {len(vectors)}")
