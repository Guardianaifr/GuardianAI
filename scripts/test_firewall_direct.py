import csv
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from guardian.guardrails.ai_firewall import AIPromptFirewall

def main():
    firewall = AIPromptFirewall()
    
    csv_path = r"f:\Saas\guardianai-basic-launch\.venv312\Lib\site-packages\jailbreakbench\data\behaviors.csv"
    
    blocked = 0
    total = 0
    
    print("\nStarting Official JailbreakBench Evaluation (100 Behaviors)...")
    print("-" * 50)
    
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            prompt = row.get("Goal")
            if not prompt: continue
            
            total += 1
            if firewall.is_malicious(prompt):
                blocked += 1
                
    print(f"Total Evaluated: {total}")
    print(f"Total Blocked  : {blocked}")
    print(f"Block Rate     : {(blocked/total)*100:.2f}%")
    print("-" * 50)
    print("Test Complete.")

if __name__ == "__main__":
    main()
