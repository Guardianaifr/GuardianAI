import os
import json
import yaml
import time
from guardian.utils.adversarial_trainer import AdversarialTrainer
from guardian.guardrails.ai_firewall import AIPromptFirewall

def test_adversarial_loop():
    print("Starting Adversarial Self-Correction Verification...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    blocked_log_path = os.path.join(base_dir, "guardian", "data", "blocked_prompts.json")
    vector_path = os.path.join(base_dir, "guardian", "config", "jailbreak_vectors.yaml")
    
    # 1. Clear previous logs for clean test
    if os.path.exists(blocked_log_path):
        os.remove(blocked_log_path)
    
    # 2. Simulate a blocked prompt
    test_prompt = "Super novel jailbreak attempt 123"
    print(f"Simulating blocked prompt: {test_prompt}")
    with open(blocked_log_path, "w", encoding="utf-8") as f:
        json.dump([test_prompt], f)

    # 3. Initialize Trainer and Update
    config = {} # dummy config
    trainer = AdversarialTrainer(config)
    added = trainer.update_vectors()
    print(f"Trainer added {added} new patterns.")
    
    # 4. Verify YAML update
    with open(vector_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        found = any(v['text'] == test_prompt and v['category'] == 'adversarial' for v in data['vectors'])
    
    if found:
        print("SUCCESS: New pattern found in jailbreak_vectors.yaml")
    else:
        print("FAILURE: New pattern NOT found in YAML.")
        return

    # 5. Verify Firewall Reload
    firewall = AIPromptFirewall() # should load the new vector automatically in __init__ -> reload()
    # It might take a moment to encode if it's actually using sentence-transformers, 
    # but for verify logic we just check if it's in the bad_prompts list.
    if test_prompt in firewall.bad_prompts:
        print("SUCCESS: Firewall successfully reloaded with new pattern!")
    else:
        print("FAILURE: Firewall did not reload new pattern.")

if __name__ == "__main__":
    test_adversarial_loop()
