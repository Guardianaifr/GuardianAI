import os
import sys

# Import our backend
sys.path.insert(0, os.path.abspath("."))
import backend.main as main_mod

plaintext = "my_super_secret_api_key_123!"

ct1 = main_mod._agentic_encrypt_secret(plaintext)
ct2 = main_mod._agentic_encrypt_secret(plaintext)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext 1: {ct1}")
print(f"Ciphertext 2: {ct2}")
print(f"CT1 != CT2: {ct1 != ct2}")

dec1 = main_mod._agentic_decrypt_secret(ct1)
dec2 = main_mod._agentic_decrypt_secret(ct2)

print(f"Decrypt CT1: {dec1}")
print(f"Decrypt CT2: {dec2}")
print(f"Roundtrip match: {dec1 == plaintext and dec2 == plaintext}")

# Now simulate rotating JWT_SECRET
main_mod.JWT_SECRET = "totally_new_jwt_secret_value"
dec_after_rotate = main_mod._agentic_decrypt_secret(ct1)
print(f"Decrypt CT1 after JWT_SECRET rotate: {dec_after_rotate}")
print(f"Still matches: {dec_after_rotate == plaintext}")

