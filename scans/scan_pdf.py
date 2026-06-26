#!/usr/bin/env python3
"""Deep-scan a PDF for suspicious/malicious content."""
import re, sys, os, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PDF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GuardianAI_Audit_SCAN-DB48D60F1F44.pdf")

data = open(PDF_PATH, "rb").read()
print("=== PDF Binary Scan ===")
print(f"File size: {len(data)} bytes")

# 1. Extract all URLs
urls = re.findall(rb'(https?://[^\x00-\x1f\x7f-\x9f\s<>"\'\\)\]]+)', data)
seen = set()
unique_urls = []
for u in urls:
    decoded = u.decode("latin-1")
    if decoded not in seen:
        seen.add(decoded)
        unique_urls.append(decoded)

print(f"\n=== URLs found ({len(unique_urls)} unique): ===")
for u in unique_urls:
    flag = ""
    sus_domains = ["bit.ly", "tinyurl", "t.co", "is.gd", "rebrand.ly", "cutt.ly",
                   "ngrok", "trycloudflare", "serveo", "localhost", "127.0.0.1",
                   "pastebin", "ipfs.io", "dweb.link", "arweave"]
    for sd in sus_domains:
        if sd in u.lower():
            flag = " [!!! SUSPICIOUS SHORTENER/TUNNEL]"
    if "polymarket" in u.lower():
        flag += " [POLYMARKET]"
    print(f"  {u}{flag}")

# 2. JavaScript / action payloads
print("\n=== Suspicious PDF Action Patterns: ===")
action_patterns = [
    (b"/JavaScript", "Embedded JavaScript"),
    (b"/JS ", "JavaScript action (short form)"),
    (b"/JS(", "JavaScript action with payload"),
    (b"/OpenAction", "Auto-execute on open"),
    (b"/AA ", "Additional actions (auto-trigger)"),
    (b"/Launch", "Launch external application"),
    (b"/SubmitForm", "Form submission to URL"),
    (b"/ImportData", "Import external data"),
    (b"/RichMedia", "Rich media / Flash embed"),
    (b"/GoToR", "Open remote PDF"),
    (b"/GoToE", "Open embedded file"),
    (b"/URI", "URI link action"),
    (b"/EmbeddedFile", "Embedded file attachment"),
    (b"/AcroForm", "Interactive form"),
    (b"/XFA", "XFA form (dynamic)"),
    (b"/Flash", "Flash content"),
    (b"eval(", "JavaScript eval()"),
    (b"fetch(", "JavaScript fetch()"),
    (b"XMLHttpRequest", "XHR request"),
    (b"document.location", "JS redirect"),
    (b"window.open", "JS popup"),
    (b".approve(", "Token approval call"),
    (b"transferFrom", "Token transferFrom call"),
    (b"setApprovalForAll", "NFT approval call"),
    (b"connect(", "Wallet connect pattern"),
    (b"eth_sendTransaction", "Ethereum tx pattern"),
    (b"signTypedData", "EIP-712 signing pattern"),
    (b"personal_sign", "Personal sign pattern"),
]

found_any = False
for pat, desc in action_patterns:
    matches = [m.start() for m in re.finditer(re.escape(pat), data)]
    if matches:
        found_any = True
        for pos in matches:
            ctx_start = max(0, pos - 40)
            ctx_end = min(len(data), pos + 60)
            context = data[ctx_start:ctx_end]
            ctx_str = context.decode("latin-1", errors="replace")
            ctx_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '.', ctx_str)
            print(f"  [ALERT] {desc}")
            print(f"     Pattern: {pat.decode('latin-1')}")
            print(f"     Offset:  {pos}")
            print(f"     Context: ...{ctx_str}...")
            print()

if not found_any:
    print("  [OK] No suspicious action patterns found")

# 3. Ethereum addresses
print("\n=== Ethereum Addresses: ===")
eth_addrs = re.findall(rb'(0x[0-9a-fA-F]{40})', data)
eth_unique = list(dict.fromkeys([a.decode() for a in eth_addrs]))
if eth_unique:
    for a in eth_unique:
        print(f"  {a}")
else:
    print("  None found")

# 4. PDF structure analysis
print("\n=== PDF Structure: ===")
obj_count = len(re.findall(rb'\d+ \d+ obj', data))
stream_count = len(re.findall(rb'stream\r?\n', data))
print(f"  Objects: {obj_count}")
print(f"  Streams: {stream_count}")

if b"/Encrypt" in data:
    print("  [WARNING] PDF is ENCRYPTED")
else:
    print("  Not encrypted")

filters = re.findall(rb'/Filter\s*/(\w+)', data)
filter_names = [f.decode() for f in filters]
print(f"  Stream filters: {', '.join(set(filter_names)) if filter_names else 'none'}")

# 5. Text extraction
print("\n=== Readable Text Snippets (first 3000 chars): ===")
text_chunks = []
for m in re.finditer(rb'stream\r?\n(.+?)\r?\nendstream', data, re.DOTALL):
    chunk = m.group(1)
    printable = sum(1 for b in chunk if 32 <= b < 127)
    if len(chunk) > 0 and printable / len(chunk) > 0.7:
        text_chunks.append(chunk.decode("latin-1", errors="replace"))

all_text = "\n---\n".join(text_chunks)
if all_text:
    print(all_text[:3000])
else:
    print("  (No easily readable text streams - content may be compressed)")
    paren_text = re.findall(rb'\(([^\)]{10,})\)', data)
    readable = [t.decode("latin-1", errors="replace") for t in paren_text
                if sum(1 for b in t if 32 <= b < 127) / max(len(t),1) > 0.8]
    if readable:
        print("\n  Text from PDF string objects:")
        for t in readable[:40]:
            print(f'    "{t}"')

# 6. Check for Polymarket-specific references
print("\n=== Polymarket-Specific Content: ===")
poly_patterns = [b"polymarket", b"Polymarket", b"POLYMARKET", b"prediction market",
                 b"poly_market", b"pm_wallet", b"USDC", b"usdc"]
for pat in poly_patterns:
    count = data.count(pat)
    if count > 0:
        print(f"  Found '{pat.decode()}' x{count}")
        positions = [m.start() for m in re.finditer(re.escape(pat), data)]
        for pos in positions[:3]:
            ctx = data[max(0,pos-30):pos+50].decode("latin-1", errors="replace")
            ctx = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '.', ctx)
            print(f"    Context: ...{ctx}...")

print("\n=== SCAN COMPLETE ===")
