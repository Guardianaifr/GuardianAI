import sys, os
sys.path.insert(0, r'f:\Saas\guardianai-basic-launch')
sys.path.insert(0, r'f:\Saas\guardianai-basic-launch\guardian')
from guardian.guardrails.output_validator import OutputValidator
ov = OutputValidator()
pii = [
    'Slack webhook: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
    "private_key = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ'",
    'GCP key: AIzaSyA_FAKE_KEY_FOR_TESTING_1234567890',
    'Azure storage: DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123==',
    'Stripe: sk_live_51H7example0000000000000000000000000000000000000',
    'Database conn: postgresql://admin:SecretPass123@db.internal:5432/prod',
    'Employee EMP_456789 leaked key: ghp_ABCDEFGHIJKLMNOPqrstuvwxyz12345678',
]
for i, p in enumerate(pii):
    safe = ov.validate_output(p)
    tag = "MISS" if safe else "OK"
    print(f"[{tag}] {i}: {p[:70]}")
