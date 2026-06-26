import json
import time
import os
import requests
import jailbreakbench as jbb

PROXY_URL = "http://127.0.0.1:8081/v1/chat/completions"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer 5a98a95f112930867b69e20d1b7495edc51ef6f7931a9175"
}

def run_official_jbb():
    print("Loading Official JailbreakBench Dataset...")
    try:
        dataset = jbb.read_dataset()
        behaviors = dataset.behaviors
    except Exception as e:
        print(f"Error loading dataset: {e}")
        return

    print(f"Loaded {len(behaviors)} behaviors. Testing proxy...")
    
    blocked_count = 0
    total_count = 0
    
    results = []

    for item in behaviors:
        prompt = item.prompt
        behavior_str = item.behavior
        
        payload = {
            "model": "openclaw",
            "messages": [{"role": "user", "content": prompt}]
        }
        
        total_count += 1
        try:
            res = requests.post(PROXY_URL, json=payload, headers=HEADERS, timeout=10)
            if res.status_code == 403:
                blocked_count += 1
                jailbroken = False
                response_text = "I cannot fulfill this request. (Blocked by GuardianAI)"
            else:
                jailbroken = True
                response_text = res.text
        except Exception as e:
            jailbroken = False
            response_text = "Error connecting to proxy"
            # If the proxy is completely down, we just mark as blocked/error
            pass

        results.append({
            "behavior": behavior_str,
            "prompt": prompt,
            "response": response_text,
            "jailbroken": jailbroken
        })
        
        print(f"Tested {total_count}/{len(behaviors)} - Blocked: {blocked_count}", end="\r")
        time.sleep(0.05)

    print(f"\n\n--- Final Results ---")
    print(f"Total Behaviors Tested : {total_count}")
    print(f"Total Blocked          : {blocked_count}")
    print(f"Block Rate             : {(blocked_count / total_count) * 100:.2f}%")
    
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence"))
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "official_jbb_results.json")
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"Detailed results saved to {out_file}")

if __name__ == "__main__":
    run_official_jbb()
