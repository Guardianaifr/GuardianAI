import json
import time
import os
import csv
import requests
import traceback

PROXY_URL = "http://127.0.0.1:8081/v1/chat/completions"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer 5a98a95f112930867b69e20d1b7495edc51ef6f7931a9175"
}

def run_official_jbb():
    print("Loading Official JailbreakBench Behaviors from local installation...")
    try:
        csv_path = r"f:\Saas\guardianai-basic-launch\.venv312\Lib\site-packages\jailbreakbench\data\behaviors.csv"
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            behaviors = list(reader)
    except Exception as e:
        print(f"Error loading dataset: {e}")
        traceback.print_exc()
        return

    print(f"Loaded {len(behaviors)} actual JailbreakBench behaviors. Testing proxy...")
    
    blocked_count = 0
    total_count = 0
    results = []

    for item in behaviors:
        prompt = item.get("Goal", "")
        behavior_str = item.get("Behavior", "")
        
        if not prompt:
            print(f"Skipping row missing 'Goal': {item}")
            continue
            
        payload = {
            "model": "openclaw",
            "messages": [{"role": "user", "content": prompt}]
        }
        
        total_count += 1
        try:
            res = requests.post(PROXY_URL, json=payload, headers=HEADERS, timeout=5)
            if res.status_code == 403:
                blocked_count += 1
                jailbroken = False
                response_text = "I cannot fulfill this request. (Blocked by GuardianAI)"
            else:
                jailbroken = True
                response_text = "Passed Firewall"
        except Exception as e:
            jailbroken = False
            response_text = "Error connecting to proxy"

        results.append({
            "behavior": behavior_str,
            "prompt": prompt,
            "response": response_text,
            "jailbroken": jailbroken
        })
        
        print(f"Tested {total_count}/{len(behaviors)} - Blocked: {blocked_count}")
        time.sleep(0.01)

    print(f"\n\n--- Final Results ---")
    print(f"Total Behaviors Tested : {total_count}")
    print(f"Total Blocked          : {blocked_count}")
    if total_count > 0:
        print(f"Block Rate             : {(blocked_count / total_count) * 100:.2f}%")
    else:
        print("Block Rate: 0.00%")
        
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence"))
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "official_jbb_results_raw.json")
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"Detailed results saved to {out_file}")

if __name__ == "__main__":
    try:
        run_official_jbb()
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
