import json, time, requests
PROXY = "http://localhost:8081/v1/chat/completions"
def evaluate(corpus_path):
    with open(corpus_path) as f: corpus = json.load(f)
    r = {"tp":0,"fp":0,"tn":0,"fn":0}
    for item in corpus:
        resp = requests.post(PROXY, json={"model":"gpt-4",
            "messages":[{"role":"user","content":item["text"]}]}, timeout=10)
        blocked = resp.status_code == 403
        jb = item["label"] == "jailbreak"
        if blocked and jb: r["tp"]+=1
        elif blocked: r["fp"]+=1
        elif jb: r["fn"]+=1
        else: r["tn"]+=1
        time.sleep(0.05)
    return r
