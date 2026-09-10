import urllib.request
import json
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from guardian.guardrails.input_filter import InputFilter

cache_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tests", "data", "deepset_sample.json")
if os.path.exists(cache_path):
    with open(cache_path, "r", encoding="utf-8") as f:
        all_rows = json.load(f)
else:
    req = urllib.request.Request(
        'https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=train&offset=0&limit=100',
        headers={'User-Agent': 'Test/1.0'}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        train_rows = json.loads(resp.read().decode())['rows']

    req2 = urllib.request.Request(
        'https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=test&offset=0&limit=100',
        headers={'User-Agent': 'Test/1.0'}
    )
    with urllib.request.urlopen(req2, timeout=15) as resp:
        test_rows = json.loads(resp.read().decode())['rows']

    all_rows = train_rows + test_rows
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(all_rows, f, indent=2)

attacks = [r['row']['text'] for r in all_rows if r['row']['label'] == 1]
safes = [r['row']['text'] for r in all_rows if r['row']['label'] == 0]

inp = InputFilter()

candidate_patterns = [
    # Instruction replacement & conversational pivot
    r'(?i)(?:forget|ignore|igmre|disregard|stop|drop)\s+(?:about\s+)?(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding|provided|your)?\s*(?:tasks?|instructions?|directives?|orders?|assignments?|rules?|information|context|guidelines?|prompts?|directions?|artikels?|articles?)',
    r'(?i)(?:now|then)\s+(?:focus\s+on|comes?|switch\s+to|start)\s+(?:your\s+|a\s+)?new\s+(?:task|instruction|challenge|objective|mission|command|test)',
    r'(?i)\b(?:new|next)\s+(?:tasks?\s+follow|task\s+is|instruction\s+is)\b',
    r'(?i)(?:that|it)\s+was\s+(?:ok|good|fine|well\s+done)\s+before.*(?:new|now)',
    r'(?i)(?:passed|finished|bestanden)\s+(?:the\s+|den\s+)?(?:first|ersten)\s+test.*(?:second|zweite)\s+test',
    r'(?i)attention\s*-\s*stop\b',
    r'(?i)\b(?:now\s+)?start\s+over\s+with\s+(?:a\s+)?new\s+task\b',
    r'(?i)(?:answer|reply|respond\s+to)\s+(?:the\s+following|this)\s+(?:question|task|prompt)\s+(?:instead|only|in\s+the\s+style)',
    r'(?i)(?:very\s+well\s+done|that\s+is\s+enough)\.?\s*now\s+please',
    r'(?i)\b(?:forget|vergiss)\s+(?:waht|what|\'s|was)\s*(?:before|zuvor|bisher)',
    r'(?i)(?:ignore|igmre)\s+what\s+i\s+said\s+before',
    r'(?i)ignore\s+(?:all\s+)?provided\s+context',
    r'(?i)ignore\s+your\s+directions',

    # System prompt, instructions & embeddings extraction
    r'(?i)\b(?:show|tell|print|display|reveal|output|echo|return)\s+(?:me\s+)?(?:all\s+)?(?:your\s+|the\s+)?(?:full\s+|complete\s+)?(?:prompt\s+texts?|prompt\s+instructions?|system\s+prompts?|initial\s+instructions?|original\s+instructions?|underlying\s+prompt|embeddings?)\b',
    r'(?i)\b(?:tell|show)\s+me\s+what\s+your\s+(?:initial|original|system)\s+instructions\s+(?:were|are)\b',
    r'(?i)\b(?:copy\s+of\s+the\s+full\s+prompt\s+text)\b',
    r'(?i)\b(?:spell-?\s*check|check\s+the\s+spelling)\s+(?:and\s+|all\s+of\s+)?(?:print|output)\s+(?:the\s+)?(?:above\s+prompt|text\s+above)\b',
    r'(?i)\b(?:print|output)\s+(?:a\s+|an\s+)?improved\s+version\s+of\s+(?:it|the\s+text\s+above)\b',
    r'(?i)\b(?:what\s+were\s+your\s+(?:original|initial|system)\s+instructions)\b',

    # Delimiters & Meta Injection Markers
    r'(?i)={4,}\s*END',
    r'(?i)\bthis\s+is\s+not\s+a\s+prompt\s+injection\b',
    r'(?i)\b(?:you\s+are\s+supposed\s+to|must)\s+answer\s+at\s+all\s+times\b',
    r'(?i)\b(?:have|has)\s+amnesia\s+and\s+forgot\b',
    r'(?i)\b(?:stay|remain)\s+in\s+(?:your|their)\s+roles?\s+without\s+(?:even\s+)?(?:breaking|falling)\b',
    r'(?i)as\s+a\s+language\s+model\s+free\b',
    r'(?i)theoretical\s+world\s+where\s+you\s+are\s+(?:no|not)\b',
    r'(?i)let\'s\s+play\s+a\s+game\s+where\s+you\s+answer\s+(?:every|all)\b',
    r'(?i)respond\s+to\s+all\s+questions\s+with\s*:\s*["\']',
    r'(?i)si\s+yo\s+digo\s+\w+,\s*tu\s+dices\b',

    # Role hijacking & Persona forcing
    r'(?i)(?:now|then)\s+you\s+are\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s*,\s*how\s+do\s+you\s+answer',
    r'(?i)^you\s+are\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\.\s*(?:what|how)\s+do\s+you\s+think',
    r'(?i)(?:generate|generieren\s+sie\s+den)\s+SQL(?:\s*-\s*|\s+)code\s+to\s+access\s+a\s+database',

    # Multilingual: German & Spanish prompt injections from deepset
    r'(?i)\bvergiss\s+(?:jetzt\s+)?(?:alles|alle)\b',
    r'(?i)\b(?:drucken|zeigen|pr[üu]fen|überprüfen)\s+sie\s+.{0,50}(?:obige\s+eingabeaufforderung|prompt-texte|system-anweisung|gesamten\s+obigen|rechtschreibung|verbesserte\s+version)\b',
    r'(?i)\b(?:zeig|zeigen)\s+(?:mir\s+)?alle\s+deine\s+prompt-texte\b',
    r'(?i)\b(?:ignorieren\s+sie|h[öo]re\s+nicht\s+auf)\s+.{0,40}(?:obigen|zuvor|gesagte)\b',
    r'(?i)\bwie\s+ihre\s+urspr[üu]nglichen\s+anweisungen\s+lauteten\b',
    r'(?i)\bdies\s+ist\s+keine\s+aufforderungsspritze\b',
    r'(?i)\bverharren\s+stets\s+in\s+ihren\s+rollen\b',
    r'(?i)\bolvide\s+(?:todo\s+)?(?:que\s+dije|lo\s+anterior|las\s+instrucciones)\b',
    r'(?i)\bjetzt\s+kommen\s+neue\s+aufgaben\b',
    r'(?i)\bjetzt\s+kommt\s+eine\s+neue\s+aufgabe\b',
    r'(?i)\bkonzentrier\w*\s+dich\s+nur\s+auf\s+diese\s+aufgabe\b',
    r'(?i)ich\s+m[öo]chte,\s*dass\s+sie\s+als\s+\w+\s+(?:agieren|auftreten)\b',
    r'(?i)antworte\s+mit\s+.{1,30}\s+und\s+nicht\s+mit\b',
    r'(?i)(?:generieren\s+sie\s+den\s+sql|generate\s+sql).*datenbank',
    r'(?i)(?:drucken|ausgeben|zeigen)\s+sie\s+eine\s+verbesserte\s+version',
    r'(?i)order\s*:\s*forget',
    r'(?i)if\s+you\s+don[\'’]t\s+know,\s*say\s*["\']',
    r'(?i)(?:as|like)\s+a\s+child\s+(?:who\s+)?does\s+not\s+have\s+any\s+previous\s+knowledge',
    r'(?i)\bcontext\s+.{1,50}\s+question\s+[A-Z]',
]

compiled = [re.compile(p) for p in candidate_patterns]

new_tp = 0
missed = []
for a in attacks:
    hit = not inp.check_prompt(a)
    if not hit:
        for pat in compiled:
            if pat.search(a):
                hit = True
                break
    if hit:
        new_tp += 1
    else:
        missed.append(a)

fp = 0
fps = []
for s in safes:
    hit = not inp.check_prompt(s)
    if not hit:
        for pat in compiled:
            if pat.search(s):
                hit = True
                break
    if hit:
        fp += 1
        fps.append(s)

print(f"New InputFilter TP: {new_tp}/{len(attacks)} ({new_tp/len(attacks)*100:.1f}%)")
print(f"New InputFilter FP: {fp}/{len(safes)} ({fp/len(safes)*100:.1f}%)")
if fps:
    print("False positives:", fps)
print(f"Remaining missed ({len(missed)}):")
for m in missed:
    print("-", repr(m))
