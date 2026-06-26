"""
Diagnoses exactly which prompts and encoding types fail detection,
then prints the first 120 chars of the DECODED text so we can
write targeted fixes.
"""
import sys, os, random, urllib.parse, logging
logging.disable(logging.CRITICAL)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "guardian")))

from datasets import load_dataset
from guardrails.input_filter import InputFilter
from guardrails.ai_firewall import AIPromptFirewall
from guardrails.encoding_detector import EncodingDetector

CHAR_TO_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
    "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
    "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
    "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
    "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
    "Z": "--..", " ": "/"
}

def to_morse(t):
    return " ".join(CHAR_TO_MORSE.get(c.upper(), "") for c in t if c.upper() in CHAR_TO_MORSE or c == " ")

encodings = {
    "Standard Morse":        lambda t: to_morse(t),
    "Written Morse":         lambda t: to_morse(t).replace(".", "dot ").replace("-", "dash ").replace("/", "slash "),
    "Asterisk/Underscore":   lambda t: to_morse(t).replace(".", "*").replace("-", "_"),
    "URL Encoded Morse":     lambda t: urllib.parse.quote(to_morse(t)),
    "Em-Dash Morse":         lambda t: to_morse(t).replace("-", "\u2014"),
}

dataset = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
prompts = dataset["Prompt"]
random.seed(99)
test_prompts = random.sample(prompts, 10)

f   = InputFilter()
fw  = AIPromptFirewall()
det = EncodingDetector()

print("=" * 70)
print("  FAILING MORSE TEST DIAGNOSIS")
print("=" * 70)

fails = []
for i, prompt in enumerate(test_prompts, 1):
    for enc_name, enc_func in encodings.items():
        encoded = enc_func(prompt)
        blocked = (not f.check_prompt(encoded)) or fw.is_malicious(encoded, mode="balanced")
        if not blocked:
            decoded_variants = det.decode_all(encoded)
            fails.append({
                "index": i,
                "enc": enc_name,
                "original": prompt,
                "encoded_preview": encoded[:80],
                "decoded_variants": decoded_variants,
            })

if not fails:
    print("ALL PASS - nothing to diagnose!")
else:
    for r in fails:
        print(f"\n[{r['index']}] FAIL via {r['enc']}")
        print(f"  Original : {r['original'][:100].strip().replace(chr(10),' ')}")
        print(f"  Encoded  : {r['encoded_preview']}")
        if r["decoded_variants"]:
            print(f"  Decoded  : {r['decoded_variants'][0][:100]}")
        else:
            print(f"  Decoded  : (NOTHING - detector did not decode)")

print(f"\n{len(fails)} total failures out of {len(test_prompts) * len(encodings)} tests")
