import sys
import os
import random
import codecs
import urllib.parse
import base64

# Ensure guardian is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "guardian")))

try:
    from datasets import load_dataset
except ImportError:
    print("Please install datasets package: pip install datasets")
    sys.exit(1)

from guardrails.input_filter import InputFilter
from guardrails.ai_firewall import AIPromptFirewall

# -----------------------------------------------------------------------------
# Encoding Utility Functions
# -----------------------------------------------------------------------------

def encode_base64(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def encode_hex(text):
    return " ".join(f"0x{ord(c):02x}" for c in text)

def encode_binary(text):
    return " ".join(f"{ord(c):08b}" for c in text)

def encode_rot13(text):
    return codecs.encode(text, "rot_13")

def encode_url(text):
    return urllib.parse.quote(text)

def encode_braille(text):
    # Mapping for common english lowercase to braille
    braille_map = {
        'a': '⠁', 'b': '⠃', 'c': '⠉', 'd': '⠙', 'e': '⠑',
        'f': '⠋', 'g': '⠛', 'h': '⠓', 'i': '⠊', 'j': '⠚',
        'k': '⠅', 'l': '⠇', 'm': '⠍', 'n': '⠝', 'o': '⠕',
        'p': '⠏', 'q': '⠟', 'r': '⠗', 's': '⠎', 't': '⠞',
        'u': '⠥', 'v': '⠧', 'w': '⠺', 'x': '⠭', 'y': '⠽',
        'z': '⠵', ' ': '⠀'
    }
    return "".join(braille_map.get(c.lower(), c) for c in text)

def encode_homoglyph(text):
    homoglyphs = {'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'x': 'х'}
    return "".join(homoglyphs.get(c, c) for c in text)

# -----------------------------------------------------------------------------
# Main Test
# -----------------------------------------------------------------------------

def run_online_dataset_tests():
    print("============================================================")
    print(" REAL-WORLD ONLINE DATASET ENCODING TEST ")
    print("============================================================")
    print("Fetching dataset 'JailbreakBench/JBB-Behaviors' from HuggingFace...")
    
    try:
        # Load the JailbreakBench dataset from HuggingFace
        dataset = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
        behaviors = dataset["Goal"]
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    # Select 10 random malicious behaviors to test
    random.seed(42) # Deterministic for reproducibility
    test_behaviors = random.sample(behaviors, 10)
    
    # Initialize GuardianAI modules
    input_filter = InputFilter()
    firewall = AIPromptFirewall()
    
    encodings = {
        "Base64": encode_base64,
        "Hex": encode_hex,
        "Binary": encode_binary,
        "ROT13": encode_rot13,
        "Braille": encode_braille,
        "Homoglyph": encode_homoglyph,
        "URL Encoded (Plain)": encode_url,
    }
    
    total_tests = 0
    passed_blocks = 0
    
    for i, behavior in enumerate(test_behaviors, 1):
        print(f"\n[{i}/{len(test_behaviors)}] Behavior: {behavior[:60]}...")
        
        # Test against all encodings
        for enc_name, enc_func in encodings.items():
            encoded_payload = enc_func(behavior)
            
            # The attack is 'passed' if the system blocks it
            blocked_by_filter = not input_filter.check_prompt(encoded_payload)
            blocked_by_firewall = firewall.is_malicious(encoded_payload, mode="balanced")
            
            is_blocked = blocked_by_filter or blocked_by_firewall
            
            total_tests += 1
            if is_blocked:
                passed_blocks += 1
                status = "PASS (Blocked)"
            else:
                status = "FAIL (Bypassed)"
                
            print(f"  -> {enc_name:20}: {status}")

    print("\n============================================================")
    print(f" Total Tests: {total_tests} | Successfully Blocked: {passed_blocks} | Failed: {total_tests - passed_blocks}")
    print(f" Defense Success Rate: {(passed_blocks / total_tests) * 100:.1f}%")
    print("============================================================")

if __name__ == "__main__":
    run_online_dataset_tests()
