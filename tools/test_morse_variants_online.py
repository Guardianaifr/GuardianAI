import sys
import os
import random
import urllib.parse
from datasets import load_dataset

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "guardian")))

from guardrails.input_filter import InputFilter

# -----------------------------------------------------------------------------
# Morse Code Encoders
# -----------------------------------------------------------------------------
CHAR_TO_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--",
    "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", " ": "/"
}

def to_morse(text):
    return " ".join(CHAR_TO_MORSE.get(c.upper(), "") for c in text if c.upper() in CHAR_TO_MORSE or c == " ")

def encode_morse_standard(text):
    return to_morse(text)

def encode_morse_written(text):
    morse = to_morse(text)
    return morse.replace(".", "dot ").replace("-", "dash ").replace("/", "slash ")

def encode_morse_asterisk_underscore(text):
    morse = to_morse(text)
    return morse.replace(".", "*").replace("-", "_")

def encode_morse_url_encoded(text):
    return urllib.parse.quote(to_morse(text))

def encode_morse_em_dash(text):
    morse = to_morse(text)
    return morse.replace("-", "—") # Em-dash

# -----------------------------------------------------------------------------
# Main Test
# -----------------------------------------------------------------------------

def run_morse_dataset_tests():
    print("============================================================")
    print(" EXTREME MORSE CODE VARIANTS BENCHMARK ")
    print("============================================================")
    
    try:
        dataset = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
        prompts = dataset["Prompt"]
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    random.seed(99)
    test_prompts = random.sample(prompts, min(10, len(prompts)))
    
    input_filter = InputFilter()
    
    encodings = {
        "Standard Morse": encode_morse_standard,
        "Written Morse": encode_morse_written,
        "Asterisk/Underscore": encode_morse_asterisk_underscore,
        "URL Encoded Morse": encode_morse_url_encoded,
        "Em-Dash Morse": encode_morse_em_dash,
    }
    
    total_tests = 0
    passed_blocks = 0
    
    for i, prompt in enumerate(test_prompts, 1):
        display = (prompt[:60] + "...") if len(prompt) > 60 else prompt
        display = display.replace('\n', ' ')
        print(f"\n[{i}/10] Jailbreak: {display}")
        
        for enc_name, enc_func in encodings.items():
            encoded_payload = enc_func(prompt)
            
            # The attack is 'passed' if the system blocks it
            blocked_by_filter = not input_filter.check_prompt(encoded_payload)
            
            is_blocked = blocked_by_filter
            total_tests += 1
            if is_blocked:
                passed_blocks += 1
                status = "PASS (Blocked)"
            else:
                status = "FAIL (Bypassed)"
                
            print(f"  -> {enc_name:25}: {status}")

    print("\n============================================================")
    print(f" Total Tests: {total_tests} | Successfully Blocked: {passed_blocks} | Failed: {total_tests - passed_blocks}")
    print(f" Morse Defense Success Rate: {(passed_blocks / total_tests) * 100:.1f}%")
    print("============================================================")

if __name__ == "__main__":
    run_morse_dataset_tests()
