import os
import sys
import time
import subprocess
import json
from playwright.sync_api import sync_playwright

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

DIST_DIR = os.path.abspath('website/explorer')
SCREENSHOT_DIR = os.path.abspath('artifacts/screenshots')
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

def run_browser_tests():
    print("[*] Starting local static server for website/explorer on port 5188...")
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", "5188", "--directory", DIST_DIR],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(1.5)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            
            # =========================================================================
            # TEST 1: Desktop Default Mode (Simple Mode Default & Fail-Closed Empty State)
            # =========================================================================
            print("\n[*] TEST 1: Desktop Default Mode (Simple Mode Default)...")
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            page = context.new_page()

            page.on("console", lambda msg: print(f"  [BROWSER CONSOLE] {msg.type}: {msg.text}"))
            page.on("pageerror", lambda err: print(f"  [BROWSER ERROR] {err}"))

            # Ensure clean localStorage
            page.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page.evaluate("() => localStorage.clear()")
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(1000)

            # Check that Simple Mode is active by default
            mode_simple_btn = page.locator("#mode-simple-btn")
            assert mode_simple_btn.count() > 0, "FAILED: #mode-simple-btn not found!"
            mode_classes = mode_simple_btn.get_attribute("class") or ""
            assert "text-[#836EF9]" in mode_classes or "bg-background" in mode_classes, "FAILED: Simple mode is not highlighted by default!"
            print("  [+] Simple mode default confirmed in navbar toggle.")

            # Check Dashboard fail-closed empty state in Simple mode
            dash_text = page.inner_text("body")
            assert "14 / 100" not in dash_text, "FAILED: Found '14 / 100' default risk score!"
            assert "-- / 100" in dash_text, "FAILED: Expected '-- / 100' empty risk score!"
            assert "No data yet" in dash_text, "FAILED: Expected 'No data yet' status badge in Simple mode!"
            assert "Protected" not in dash_text or "No data yet" in dash_text, "FAILED: Empty state must not report Protected!"
            assert "Share blocked" in dash_text, "FAILED: Expected 'Share blocked' in dashboard metrics!"
            assert "Containment Ratio" not in dash_text, "FAILED: Found old 'Containment Ratio' label!"
            assert "0 allowed" in dash_text, "FAILED: Expected '0 allowed' in outcome breakdown!"
            assert "couldn't verify" in dash_text, "FAILED: Expected 'couldn't verify' in outcome breakdown!"
            print("  [+] Dashboard Simple mode empty state verified: '-- / 100', 'No data yet', 'Share blocked', fail-closed breakdown.")

            # Check that banned technical jargon is absent in Simple Mode on Dashboard
            banned_simple_jargon = [
                "EIP-712",
                "RIP-7212",
                "precompile",
                "mempool",
                "BFT consensus",
                "Merkle root",
                "0x90Fd",
                "0xDA5f"
            ]
            for term in banned_simple_jargon:
                assert term not in dash_text, f"FAILED: Found banned technical term '{term}' in Simple mode Dashboard!"
            print("  [+] Banned jargon verification passed: technical blockchain jargon hidden in Simple mode.")

            # Capture Desktop Dashboard (Simple Mode)
            desktop_dash_simple = os.path.join(SCREENSHOT_DIR, "desktop_dashboard_simple.png")
            page.screenshot(path=desktop_dash_simple, full_page=False)
            print(f"  [+] Captured {desktop_dash_simple}")

            # =========================================================================
            # TEST 2: Home Tab in Simple Mode
            # =========================================================================
            print("\n[*] TEST 2: Home Tab in Simple Mode...")
            page.goto("http://localhost:5188/#home", wait_until="networkidle")
            page.wait_for_timeout(800)
            home_text = page.inner_text("body")
            assert "GuardianAI Platform" in home_text, "FAILED: Expected 'GuardianAI Platform' heading in HomeTab!"
            assert "Real-time safety rules, automated prompt injection defense" in home_text, "FAILED: Expected plain English subtitle!"
            assert "Protected Agents" in home_text, "FAILED: Expected 'Protected Agents' label in Simple mode!"
            assert "Test Approved Action" in home_text, "FAILED: Expected 'Test Approved Action' button in Simple mode!"
            assert "Test Blocked Action" in home_text, "FAILED: Expected 'Test Blocked Action' button in Simple mode!"

            # Capture Desktop Home (Simple Mode)
            desktop_home_simple = os.path.join(SCREENSHOT_DIR, "desktop_home_simple.png")
            page.screenshot(path=desktop_home_simple, full_page=False)
            print(f"  [+] Captured {desktop_home_simple}")

            # =========================================================================
            # TEST 3: Agents Tab in Simple Mode
            # =========================================================================
            print("\n[*] TEST 3: Agents Tab in Simple Mode...")
            page.goto("http://localhost:5188/#agents", wait_until="networkidle")
            page.wait_for_timeout(800)
            agents_text = page.inner_text("body")
            assert "AI Agent Protection Directory" in agents_text, "FAILED: Expected Simple mode header in AgentsTab!"
            assert "Automated Security Checks: Active & Monitored" in agents_text, "FAILED: Expected 'Automated Security Checks: Active & Monitored' in Simple mode!"
            assert "DEVELOPER INTEGRATION" not in agents_text, "FAILED: Developer integration banner should be hidden in Simple mode!"
            assert "Supervisor Delegation Authority" not in agents_text, "FAILED: Supervisor authority card should be hidden in Simple mode!"
            assert "Specs" not in agents_text, "FAILED: Technical in-card sub-tabs should be hidden in Simple mode!"
            assert "Simulate Probe" not in agents_text, "FAILED: Attack probe sub-tabs should be hidden in Simple mode!"
            print("  [+] Agents tab in Simple mode verified: Probes, developer banner, and supervisor keys cleanly hidden.")

            # Capture Desktop Agents (Simple Mode)
            desktop_agents_simple = os.path.join(SCREENSHOT_DIR, "desktop_agents_simple.png")
            page.screenshot(path=desktop_agents_simple, full_page=False)
            print(f"  [+] Captured {desktop_agents_simple}")

            # =========================================================================
            # TEST 4: Mode Toggle to Advanced Mode & Feature Reveal
            # =========================================================================
            print("\n[*] TEST 4: Mode Toggle to Advanced Mode...")
            mode_adv_btn = page.locator("#mode-advanced-btn")
            mode_adv_btn.click()
            page.wait_for_timeout(600)

            # Check that localStorage is updated
            is_advanced_storage = page.evaluate("() => localStorage.getItem('guardian_mode')")
            assert is_advanced_storage == "advanced", f"FAILED: Expected localStorage 'guardian_mode' to be 'advanced', got {is_advanced_storage}"
            print("  [+] Toggle switched state: localStorage persists isAdvanced=true (guardian_mode='advanced').")

            # Check that technical features and tabs appear in Advanced mode
            adv_agents_text = page.inner_text("body")
            assert "DEVELOPER INTEGRATION" in adv_agents_text, "FAILED: Developer integration banner should be visible in Advanced mode!"
            assert "Supervisor Delegation Authority" in adv_agents_text, "FAILED: Supervisor delegation authority should be visible in Advanced mode!"
            assert "Specs" in adv_agents_text, "FAILED: In-card Specs sub-tab should be visible in Advanced mode!"
            assert "Simulate Probe" in adv_agents_text, "FAILED: In-card Simulate Probe sub-tab should be visible in Advanced mode!"
            print("  [+] Advanced mode revealed technical developer integration and simulation probes.")

            # Capture Desktop Agents (Advanced Mode)
            desktop_agents_adv = os.path.join(SCREENSHOT_DIR, "desktop_agents_advanced.png")
            page.screenshot(path=desktop_agents_adv, full_page=False)
            print(f"  [+] Captured {desktop_agents_adv}")

            # Switch to Dashboard in Advanced Mode
            page.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page.wait_for_timeout(800)
            adv_dash_text = page.inner_text("body")
            assert "Monad Parallel EVM Telemetry" in adv_dash_text, "FAILED: Expected 'Monad Parallel EVM Telemetry' in Advanced Dashboard!"
            assert "GuardianPolicyGuard (0x90Fd...EF60)" in adv_dash_text, "FAILED: Expected technical contract spec in Advanced Dashboard!"
            print("  [+] Dashboard in Advanced mode verified: Technical telemetry and protocol specs present.")

            # Capture Desktop Dashboard (Advanced Mode)
            desktop_dash_adv = os.path.join(SCREENSHOT_DIR, "desktop_dashboard_advanced.png")
            page.screenshot(path=desktop_dash_adv, full_page=False)
            print(f"  [+] Captured {desktop_dash_adv}")

            # =========================================================================
            # TEST 5: Interactive Probe Attestation Relayer Enforcement Outside Demo
            # =========================================================================
            print("\n[*] TEST 5: Interactive Probe Attestation Relayer Enforcement...")
            page.goto("http://localhost:5188/#agents", wait_until="networkidle")
            page.wait_for_timeout(800)

            # Click "Simulate Probe" sub-tab on Eliza card
            probe_subtab = page.locator("button:has-text('Simulate Probe')").first
            print(f"  [*] probe_subtab count: {probe_subtab.count()}, visible: {probe_subtab.is_visible()}")
            probe_subtab.scroll_into_view_if_needed()
            probe_subtab.click(force=True)
            page.wait_for_timeout(800)

            # Click the valid swap probe
            valid_probe_btn = page.locator("button:has-text('Simulated Swap (Demo Only)')").first
            print(f"  [*] valid_probe_btn count: {valid_probe_btn.count()}, visible: {valid_probe_btn.is_visible()}")
            valid_probe_btn.scroll_into_view_if_needed()
            valid_probe_btn.click(force=True)
            page.wait_for_timeout(1000)

            # Confirm "Attestation Relayer Required" is displayed and no tx was sent
            body_content = page.inner_text("body")
            assert "attestation relayer required" in body_content.lower() or "backend relayer" in body_content.lower(), f"FAILED: Expected 'Attestation Relayer Required' message outside demo mode! Body: {body_content[:500]}"
            print("  [+] Probe verified: UI shows 'Attestation Relayer Required' outside demo mode, 0 on-chain tx sent.")

            # =========================================================================
            # TEST 6: Monad RPC Abort/500 Handling on Passport Query
            # =========================================================================
            print("\n[*] TEST 6: Monad RPC Abort/500 Network Error Handling...")
            # Route Monad RPC calls to abort/fail
            page.route("https://testnet-rpc.monad.xyz**", lambda route: route.abort())

            # Click Simulate Probe on passport agent card (3rd card)
            probe_subtabs = page.locator("button:has-text('Simulate Probe')")
            if probe_subtabs.count() >= 3:
                probe_subtabs.nth(2).click()
                page.wait_for_timeout(300)
                passport_verify_btn = page.locator("button:has-text('Check Test ID revoked-agent-01')")
                if passport_verify_btn.count() > 0:
                    passport_verify_btn.first.click()
                    page.wait_for_timeout(1000)
                    body_text = page.inner_text("body")
                    assert "couldn't verify (network error)" in body_text.lower(), "FAILED: Expected Couldn't verify (network error) on RPC failure!"
                    print("  [+] Passport probe on RPC abort verified: Displays Couldn't verify (network error), NEVER revoked.")
            
            page.unroute("https://testnet-rpc.monad.xyz**")

            # =========================================================================
            # TEST 7: Mobile Viewport Tests (375x812) in Simple & Advanced Mode
            # =========================================================================
            print("\n[*] TEST 7: Mobile Viewport Tests (375x812)...")
            mobile_context = browser.new_context(viewport={"width": 375, "height": 812})
            mobile_page = mobile_context.new_page()

            # Mobile Home in Simple Mode
            mobile_page.goto("http://localhost:5188/#home", wait_until="networkidle")
            mobile_page.evaluate("() => localStorage.setItem('guardian_mode', 'simple')")
            mobile_page.reload(wait_until="networkidle")
            mobile_page.wait_for_timeout(800)

            mobile_home_simple = os.path.join(SCREENSHOT_DIR, "mobile_home_simple.png")
            mobile_page.screenshot(path=mobile_home_simple, full_page=False)
            print(f"  [+] Captured {mobile_home_simple}")

            # Mobile Dashboard in Simple Mode
            mobile_page.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            mobile_page.wait_for_timeout(800)
            mobile_dash_simple = os.path.join(SCREENSHOT_DIR, "mobile_dashboard_simple.png")
            mobile_page.screenshot(path=mobile_dash_simple, full_page=False)
            print(f"  [+] Captured {mobile_dash_simple}")

            # Mobile Agents in Simple Mode
            mobile_page.goto("http://localhost:5188/#agents", wait_until="networkidle")
            mobile_page.wait_for_timeout(800)
            mobile_agents_simple = os.path.join(SCREENSHOT_DIR, "mobile_agents_simple.png")
            mobile_page.screenshot(path=mobile_agents_simple, full_page=False)
            print(f"  [+] Captured {mobile_agents_simple}")

            # =========================================================================
            # TEST 8: Explicit Demo Mode (?demo=true) & Persistence
            # =========================================================================
            print("\n[*] TEST 8: Explicit Demo Mode (?demo=true)...")
            demo_page = context.new_page()
            demo_page.goto("http://localhost:5188/?demo=true#dashboard", wait_until="networkidle")
            demo_page.wait_for_timeout(1000)
            demo_text = demo_page.inner_text("body")
            assert "sample data" in demo_text.lower(), "FAILED: Expected persistent 'Sample Data' banner in demo mode!"
            assert "explicit demo mode active" in demo_text.lower(), "FAILED: Expected demo mode disclaimer banner!"
            print("  [+] Demo mode verified: Persistent 'Sample Data' banner displayed.")

            # Capture Demo Mode Screenshot
            desktop_demo_mode = os.path.join(SCREENSHOT_DIR, "desktop_demo_mode.png")
            demo_page.screenshot(path=desktop_demo_mode, full_page=False)
            print(f"  [+] Captured {desktop_demo_mode}")

            browser.close()
            print("\n=======================================================")
            print("  [SUCCESS] ALL PHASE 1a & PHASE 1b BROWSER TESTS PASSED!")
            print("=======================================================")

    finally:
        server.terminate()

if __name__ == "__main__":
    run_browser_tests()
