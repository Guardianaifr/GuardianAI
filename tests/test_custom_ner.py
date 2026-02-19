from guardian.guardrails.output_validator import OutputValidator

def test_custom_ner():
    print("Starting Custom NER Verification...")
    validator = OutputValidator()
    
    # 1. Test Core Pattern (Email)
    text1 = "Contact me at test@example.com"
    sanitized1, entities1 = validator.sanitize_output(text1)
    print(f"Test 1 (Email): {text1} -> {sanitized1}")
    
    # 2. Test Custom Pattern (Medical ID)
    text2 = "Patient ID is MID-1234-XY"
    sanitized2, entities2 = validator.sanitize_output(text2)
    print(f"Test 2 (Medical ID): {text2} -> {sanitized2}")
    
    # 3. Test Custom Pattern (Employee Code)
    text3 = "Employee EMP_654321 is on site."
    sanitized3, entities3 = validator.sanitize_output(text3)
    print(f"Test 3 (Employee Code): {text3} -> {sanitized3}")

    # 4. Test Case Insensitivity/Normalization (if applicable)
    text4 = "My secret code is mid-9999-zz"
    sanitized4, entities4 = validator.sanitize_output(text4)
    print(f"Test 4 (Case Insensitive Medical ID): {text4} -> {sanitized4}")

    # Validation
    success = True
    if "[REDACTED_EMAIL_ADDRESS]" not in sanitized1 and "[REDACTED]" not in sanitized1:
        print("Failure: Email NOT redacted.")
        success = False
    if "[REDACTED_MEDICAL_ID]" not in sanitized2:
        print("Failure: Medical ID NOT redacted.")
        success = False
    if "[REDACTED_EMPLOYEE_CODE]" not in sanitized3:
        print("Failure: Employee Code NOT redacted.")
        success = False
    
    if success:
        print("\n[SUCCESS] Verification: Custom NER models are working correctly!")
    else:
        print("\n[FAILURE] Verification failed.")

if __name__ == "__main__":
    test_custom_ner()
