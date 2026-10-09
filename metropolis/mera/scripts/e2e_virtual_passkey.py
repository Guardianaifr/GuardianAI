"""End-to-end test of website/mera/ with real WebAuthn PRF ceremonies in headless Chromium.

Chrome's DevTools virtual authenticator (hasPrf=true) stands in for the platform passkey, so the page
runs the same navigator.credentials code path a phone or laptop would. No mocks in the page.

    pip install playwright && python -m playwright install chromium
    python metropolis/mera/scripts/e2e_virtual_passkey.py [--card-out card.json]

Limitation: a virtual authenticator cannot export a credential's PRF secret, so "second device" is
modelled as the same authenticator behind a wiped page (no localStorage, no JS state, only the passkey
and the handoff link). The real cross-device test is done by hand with a synced passkey.
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

WEBSITE = Path(__file__).resolve().parents[3] / "website"
PORT = 8765
URL = f"http://localhost:{PORT}/mera/index.html"


def add_authenticator(page):
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "internal",
        "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
        "hasPrf": True, "automaticPresenceSimulation": True}})


def click(page, sel, expect_log=None):
    page.click(sel)
    page.wait_for_function("s => !document.querySelector(s).disabled", arg=sel, timeout=15000)
    if expect_log:
        page.wait_for_function("t => document.getElementById('log').innerText.includes(t)", arg=expect_log, timeout=15000)


def check(name, cond):
    print(f"{'PASS' if cond else 'FAIL'}  {name}")
    if not cond:
        raise SystemExit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--card-out")
    args = ap.parse_args()
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT), "--bind", "127.0.0.1", "-d", str(WEBSITE)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            errors = []
            a = browser.new_context().new_page()
            a.on("pageerror", lambda e: errors.append(str(e)))
            add_authenticator(a)
            a.goto(URL)

            click(a, "#btnCreate", "Passkey created")
            check("operator passkey created with PRF", True)
            click(a, "#btnDerive", "Agent DID")
            did_a = a.locator("#didOut").inner_text()
            check(f"agent DID derived ({did_a[:34]}...)", did_a.startswith("did:guardian:ed25519:"))
            click(a, "#btnSeal", "Memory sealed")
            click(a, "#btnUnseal", "Memory decrypted")
            check("memory seal/unseal round trip", "approved list" in a.locator("#memOut").inner_text())
            a.click("#btnTamper")
            click(a, "#btnUnseal", "MEMORY_POISONING_DETECTED")
            check("1-bit tamper -> MEMORY_POISONING_DETECTED + quarantine", a.locator("#quarantine").is_visible())
            click(a, "#btnSeal", "Memory sealed")
            a.fill("#vaultIn", "demo-api-key-1234567890")
            click(a, "#btnLock", "Credential locked")
            check("vault input cleared after locking", a.input_value("#vaultIn") == "")
            click(a, "#btnUnlock", "Vault unlocked")
            check("vault unlock (masked)", a.locator("#vaultOut").inner_text().startswith("demo"))
            click(a, "#btnCard", "Agent card signed")
            card = json.loads(a.locator("#cardJson").inner_text())
            check("agent card signed by the agent DID", card["did"] == did_a)
            a.click("#btnHandoff")
            a.wait_for_function("document.getElementById('handoffUrl').value.length > 0")
            link = a.input_value("#handoffUrl")
            check("handoff link carries no plaintext credential", "demo-api-key" not in link)
            stored = json.loads(a.evaluate("JSON.stringify(Object.assign({}, localStorage))"))
            check(f"only the public credential id is in browser storage {list(stored)}",
                  list(stored) == ["guardianai.mera.credentialId"])

            # "Second device": same passkey, wiped page.
            a.evaluate("localStorage.clear()")
            a.goto("about:blank")
            a.goto(link)
            click(a, "#btnDerive", "Cross-device check")
            check("handoff: same DID re-derived from the passkey alone", a.locator("#didOut").inner_text() == did_a)
            click(a, "#btnUnseal", "Memory decrypted")
            check("handoff: memory decrypted", "approved list" in a.locator("#memOut").inner_text())
            click(a, "#btnUnlock", "Vault unlocked")
            check("handoff: vault unlocked", a.locator("#vaultOut").inner_text().startswith("demo"))

            # A different passkey must get nothing.
            c = browser.new_context().new_page()
            add_authenticator(c)
            c.goto(link)
            click(c, "#btnCreate", "Passkey created")
            click(c, "#btnDerive", "Cross-device check")
            check("other passkey: different DID", c.locator("#didOut").inner_text() != did_a)
            click(c, "#btnUnseal", "MEMORY_POISONING_DETECTED")
            check("other passkey: cannot decrypt memory", c.locator("#quarantine").is_visible())

            check(f"no page errors {errors}", not errors)
            if args.card_out:
                Path(args.card_out).write_text(json.dumps(card, indent=2))
            browser.close()
    finally:
        srv.terminate()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
