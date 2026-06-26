#!/usr/bin/env python3
"""Extract text from FlateDecode PDF streams and analyze."""
import re, sys, os, io, zlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

PDF_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GuardianAI_Audit_SCAN-DB48D60F1F44.pdf")
data = open(PDF_PATH, "rb").read()

print("=== Decompressing FlateDecode streams ===\n")

all_text = []
stream_re = re.compile(rb'stream\r?\n(.*?)\r?\nendstream', re.DOTALL)

for i, m in enumerate(stream_re.finditer(data)):
    raw = m.group(1)
    try:
        decompressed = zlib.decompress(raw)
    except:
        decompressed = raw

    # Extract text from PDF text objects: BT ... ET blocks with Tj/TJ operators
    text_ops = re.findall(rb'\(([^)]*)\)\s*Tj', decompressed)
    tj_texts = [t.decode('latin-1', errors='replace') for t in text_ops]

    # Also TJ arrays: [(text) kerning (text) ...] TJ
    tj_arrays = re.findall(rb'\[((?:\([^)]*\)[^]]*)+)\]\s*TJ', decompressed)
    for arr in tj_arrays:
        parts = re.findall(rb'\(([^)]*)\)', arr)
        line = ''.join(p.decode('latin-1', errors='replace') for p in parts)
        tj_texts.append(line)

    if tj_texts:
        for t in tj_texts:
            if t.strip():
                all_text.append(t.strip())

    # Also check decompressed streams for URLs and suspicious content
    urls_in_stream = re.findall(rb'(https?://[^\x00-\x1f\x7f-\x9f\s<>"\'\\)\]]+)', decompressed)
    for u in urls_in_stream:
        print(f"  [URL in stream {i}] {u.decode('latin-1')}")

    eth_in_stream = re.findall(rb'(0x[0-9a-fA-F]{40})', decompressed)
    for e in eth_in_stream:
        print(f"  [ETH ADDR in stream {i}] {e.decode()}")

    # Check for polymarket
    if b"polymarket" in decompressed.lower():
        print(f"  [POLYMARKET REF in stream {i}]")
        ctx = decompressed[max(0, decompressed.lower().find(b"polymarket")-50):
                           decompressed.lower().find(b"polymarket")+100]
        print(f"    Context: {ctx}")

print(f"\n=== Extracted Text ({len(all_text)} fragments): ===\n")
# Print all text, joining fragments into readable form
full_text = '\n'.join(all_text)
print(full_text[:8000])

if len(full_text) > 8000:
    print(f"\n... [{len(full_text) - 8000} more characters] ...")

# Summary analysis
print("\n\n=== CONTENT ANALYSIS ===")
lower_text = full_text.lower()

keywords_sus = {
    "polymarket": 0, "prediction market": 0, "wallet": 0, "connect wallet": 0,
    "approve": 0, "smart contract": 0, "token": 0, "usdc": 0, "ethereum": 0,
    "deposit": 0, "withdraw": 0, "bridge": 0, "swap": 0, "airdrop": 0,
    "claim": 0, "reward": 0, "verify": 0, "kyc": 0, "click here": 0,
    "urgent": 0, "immediately": 0, "limited time": 0, "act now": 0,
    "private key": 0, "seed phrase": 0, "mnemonic": 0,
    "guardianai": 0, "guardian ai": 0, "audit": 0, "security": 0,
    "scan": 0, "vulnerability": 0, "threat": 0, "risk": 0,
}
for kw in keywords_sus:
    keywords_sus[kw] = lower_text.count(kw)

print("\nKeyword frequency:")
for kw, count in sorted(keywords_sus.items(), key=lambda x: -x[1]):
    if count > 0:
        print(f"  '{kw}': {count}")

print("\n=== DONE ===")
