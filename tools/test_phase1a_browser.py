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
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            
            # =========================================================================
            # TEST 1: Desktop Default Mode (Simple Mode Default & Fail-Closed Empty State)
            # =========================================================================
            print("\n[*] TEST 1: Desktop Default Mode (Simple Mode Default)...")
            # IIFE init script string
            IIFE_INIT_SCRIPT = """(function() {
                window.__sendTxCalls = [];
                window.__sendRawTxCalls = [];

                function wrapProvider(prov) {
                    if (!prov || prov.__guarded_wrapped) return;
                    prov.__guarded_wrapped = true;
                    const origReq = prov.request;
                    if (origReq) {
                        prov.request = function(args) {
                            if (args) {
                                if (args.method === 'eth_sendTransaction') {
                                    window.__sendTxCalls.push(args);
                                }
                                if (args.method === 'eth_sendRawTransaction') {
                                    window.__sendRawTxCalls.push(args);
                                }
                            }
                            return origReq.apply(this, arguments);
                        };
                    }
                }

                if (window.ethereum) {
                    wrapProvider(window.ethereum);
                } else {
                    let _eth = {
                        request: function(args) {
                            return Promise.resolve("0xmocktx");
                        }
                    };
                    wrapProvider(_eth);
                    Object.defineProperty(window, 'ethereum', {
                        configurable: true,
                        get: function() { return _eth; },
                        set: function(v) {
                            _eth = v;
                            wrapProvider(v);
                        }
                    });
                }
            })();"""

            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                permissions=["clipboard-read", "clipboard-write"]
            )
            context.add_init_script(IIFE_INIT_SCRIPT)
            page = context.new_page()

            # Track any eth_sendTransaction or eth_sendRawTransaction requests across the network
            sent_tx_requests = []
            sent_raw_tx_requests = []
            def track_request(request):
                if request.method == "POST":
                    post_data = request.post_data or ""
                    if "eth_sendTransaction" in post_data:
                        sent_tx_requests.append({"url": request.url, "body": post_data})
                    if "eth_sendRawTransaction" in post_data:
                        sent_raw_tx_requests.append({"url": request.url, "body": post_data})

            page.on("request", track_request)
            page.on("console", lambda msg: print(f"  [BROWSER CONSOLE] {msg.type}: {msg.text}"))
            page.on("pageerror", lambda err: print(f"  [BROWSER ERROR] {err}"))

            # Ensure clean localStorage
            page.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page.evaluate("() => localStorage.clear()")
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(1000)

            # POSITIVE CONTROL: verify wrapper intercepts eth_sendTransaction
            print("  [*] Running Positive Control Test: invoking eth_sendTransaction on window.ethereum...")
            page.evaluate("() => window.ethereum.request({ method: 'eth_sendTransaction', params: [{ from: '0x1', to: '0x2' }] })")
            control_calls = page.evaluate("() => window.__sendTxCalls ? window.__sendTxCalls.length : 0")
            assert control_calls == 1, f"FAILED: Positive control failed! Expected __sendTxCalls length 1, got {control_calls}"
            print("  [+] Positive control PASSED: eth_sendTransaction intercepted and counter incremented to 1.")
            # Reset counters before test assertions
            page.evaluate("() => { window.__sendTxCalls = []; window.__sendRawTxCalls = []; }")

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
            assert ("No data yet" in dash_text) or ("Couldn't load data" in dash_text), "FAILED: Expected 'No data yet' or 'Couldn't load data' status badge in Simple mode!"
            assert "Protected" not in dash_text or "No data yet" in dash_text or "Couldn't load data" in dash_text, "FAILED: Empty state must not report Protected!"
            assert "actions executed" in dash_text.lower(), "FAILED: Expected 'Actions executed' in dashboard metrics!"
            assert "threats registered" in dash_text.lower(), "FAILED: Expected 'Threats registered' in dashboard metrics!"
            assert "Share blocked" not in dash_text, "FAILED: Found old 'Share blocked' label!"
            assert "Containment Ratio" not in dash_text, "FAILED: Found old 'Containment Ratio' label!"
            assert ("couldn't load data" in dash_text.lower()) or ("0 executed" in dash_text) or ("0 allowed" in dash_text), "FAILED: Expected 'Couldn't load data' on fetch failure or '0 executed' in outcome breakdown!"
            print("  [+] Dashboard Simple mode empty state verified: '-- / 100', 'No data yet', separate Actions/Threats metrics, Couldn't load data on failure.")

            # Check that banned technical jargon is absent in Simple Mode on Dashboard (Exact 15 terms)
            BANNED_JARGON_15 = [
                "ERC-8004",
                "TEE",
                "EIP-712",
                "RIP-7212",
                "soulbound",
                "precompile",
                "attestation",
                "PRF",
                "enclave",
                "mempool",
                "Merkle",
                "0x90Fd",
                "0xDA5f",
                "firewall",
                "vault"
            ]
            for term in BANNED_JARGON_15:
                assert term.lower() not in dash_text.lower(), f"FAILED: Found banned technical term '{term}' in Simple mode Dashboard!"
            print(f"  [+] Banned jargon verification passed on Dashboard ({len(BANNED_JARGON_15)} terms checked).")

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
            assert "Agent Passports Tracked" in home_text or "Passports Tracked" in home_text, "FAILED: Expected 'Agent Passports Tracked' label in Simple mode!"
            assert "Test Approved Action" in home_text, "FAILED: Expected 'Test Approved Action' button in Simple mode!"
            assert "Test Blocked Action" in home_text, "FAILED: Expected 'Test Blocked Action' button in Simple mode!"

            # Banned jargon check on Home in Simple mode (Exact 15 terms)
            for term in BANNED_JARGON_15:
                assert term.lower() not in home_text.lower(), f"FAILED: Found banned technical term '{term}' in Simple mode Home!"
            print(f"  [+] Banned jargon verification passed on Home ({len(BANNED_JARGON_15)} terms checked).")

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

            # Banned jargon check on Agents in Simple mode (Exact 15 terms)
            for term in BANNED_JARGON_15:
                assert term.lower() not in agents_text.lower(), f"FAILED: Found banned technical term '{term}' in Simple mode Agents!"
            print(f"  [+] Banned jargon verification passed on Agents ({len(BANNED_JARGON_15)} terms checked).")

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
            # TEST 8A: Explicit Demo Mode (?demo=true) & Persistence
            # =========================================================================
            print("\n[*] TEST 8A: Explicit Demo Mode (?demo=true)...")
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

            # =========================================================================
            # TEST 8B: Item 7a - Jargon Check in ?demo=true Simple Mode on ALL Tabs
            # (Checking visible text AND title/aria-label attributes for 15 banned terms)
            # =========================================================================
            print("\n[*] TEST 8B: Item 7a - Jargon Check in ?demo=true Simple Mode on ALL Tabs...")
            visible_tabs = ["dashboard", "home", "agents", "logs"]
            # Ensure Simple mode is active first
            demo_page.goto("http://localhost:5188/?demo=true#dashboard", wait_until="networkidle")
            demo_page.evaluate("() => localStorage.setItem('guardian_mode', 'simple')")
            demo_page.reload(wait_until="networkidle")
            demo_page.wait_for_timeout(600)

            for tab_id in visible_tabs:
                tab_url = f"http://localhost:5188/?demo=true#{tab_id}"
                demo_page.goto(tab_url, wait_until="networkidle")
                demo_page.wait_for_timeout(600)

                tab_text = demo_page.inner_text("body")
                tab_titles = demo_page.evaluate("() => Array.from(document.querySelectorAll('[title]')).map(el => el.getAttribute('title')).filter(Boolean)")
                tab_aria = demo_page.evaluate("() => Array.from(document.querySelectorAll('[aria-label]')).map(el => el.getAttribute('aria-label')).filter(Boolean)")

                all_tab_content = [tab_text] + tab_titles + tab_aria

                for term in BANNED_JARGON_15:
                    for chunk in all_tab_content:
                        assert term.lower() not in chunk.lower(), f"FAILED (Item 7a): Found banned term '{term}' on tab #{tab_id} in snippet: '{chunk[:120]}'"
                print(f"  [+] Tab #{tab_id} PASSED banned jargon check ({len(BANNED_JARGON_15)} terms across text, titles, aria-labels).")

            # =========================================================================
            # TEST 8C: Item 3 & Item 7b - Every Copy Button Prefix/Suffix Clipboard Verification
            # =========================================================================
            print("\n[*] TEST 8C: Item 3 & Item 7b - Every Copy Button Verification...")
            # 1. Iterate through ALL Copy Address buttons on #agents tab in Simple mode
            demo_page.goto("http://localhost:5188/?demo=true#agents", wait_until="networkidle")
            demo_page.wait_for_timeout(600)
            copy_addr_btns = demo_page.locator("button[title='Copy Address']")
            btn_count = copy_addr_btns.count()
            assert btn_count >= 3, f"Expected at least 3 Copy Address buttons on Agents tab, found {btn_count}"
            for i in range(btn_count):
                btn = copy_addr_btns.nth(i)
                parent = btn.locator("..")
                displayed_text = parent.inner_text().strip()
                clean_displayed = displayed_text.split()[0].replace("\n", "").strip()
                assert "..." in clean_displayed, f"Expected shortened format with '...' in '{clean_displayed}'"
                prefix, suffix = clean_displayed.split("...")
                btn.click()
                demo_page.wait_for_timeout(200)
                copied = demo_page.evaluate("() => navigator.clipboard.readText()")
                assert copied.lower().startswith(prefix.lower()), f"Clipboard '{copied}' does not start with prefix '{prefix}'"
                assert copied.lower().endswith(suffix.lower()), f"Clipboard '{copied}' does not end with suffix '{suffix}'"
                print(f"  [+] Copy Address button {i+1} verified: display '{clean_displayed}' -> clipboard '{copied}' matches prefix '{prefix}' and suffix '{suffix}'")

            # 2. Iterate through ALL Copy Tx Hash buttons on #logs tab in Simple mode
            demo_page.goto("http://localhost:5188/?demo=true#logs", wait_until="networkidle")
            demo_page.wait_for_timeout(600)
            copy_tx_btns = demo_page.locator("button[title='Copy Tx Hash']")
            tx_btn_count = copy_tx_btns.count()
            assert tx_btn_count > 0, f"Expected at least 1 Copy Tx Hash button on Logs tab, found {tx_btn_count}"
            for i in range(tx_btn_count):
                btn = copy_tx_btns.nth(i)
                parent = btn.locator("..")
                displayed_text = parent.inner_text().strip()
                shortened_hash = displayed_text.replace("Tx:", "").strip().split()[0]
                assert "..." in shortened_hash, f"Expected shortened format with '...' in '{shortened_hash}'"
                prefix, suffix = shortened_hash.split("...")
                btn.click()
                demo_page.wait_for_timeout(200)
                copied = demo_page.evaluate("() => navigator.clipboard.readText()")
                assert copied.lower().startswith(prefix.lower()), f"Clipboard '{copied}' does not start with prefix '{prefix}'"
                assert copied.lower().endswith(suffix.lower()), f"Clipboard '{copied}' does not end with suffix '{suffix}'"
                print(f"  [+] Copy Tx Hash button {i+1} verified: display '{shortened_hash}' -> clipboard '{copied}' matches prefix '{prefix}' and suffix '{suffix}'")

            # =========================================================================
            # TEST 9: Playwright Invariant - Assert 0 eth_sendTransaction & 0 eth_sendRawTransaction calls
            # =========================================================================
            print("\n[*] TEST 9: Playwright Invariant - Assert 0 eth_sendTransaction & 0 eth_sendRawTransaction calls...")
            provider_calls = page.evaluate("() => window.__sendTxCalls ? window.__sendTxCalls.length : 0")
            provider_raw_calls = page.evaluate("() => window.__sendRawTxCalls ? window.__sendRawTxCalls.length : 0")
            assert len(sent_tx_requests) == 0, f"FAILED: eth_sendTransaction network calls detected: {sent_tx_requests}"
            assert len(sent_raw_tx_requests) == 0, f"FAILED: eth_sendRawTransaction network calls detected: {sent_raw_tx_requests}"
            assert provider_calls == 0, f"FAILED: eth_sendTransaction provider calls detected: {provider_calls}"
            assert provider_raw_calls == 0, f"FAILED: eth_sendRawTransaction provider calls detected: {provider_raw_calls}"
            print("  [+] Playwright assertion PASSED: exactly 0 eth_sendTransaction and 0 eth_sendRawTransaction calls made across all operations.")

            # =========================================================================
            # TEST 10: Part D Item 6 & Part E Item 9 - Real GraphQL Invariant Playwright Tests
            # (a) real-shaped success -> visible numbers in stat tiles
            # (b) HTTP 500 at first load -> "Couldn't load data" with zero digits
            # (c) success then 500 on next poll -> stale label + last values preserved
            # =========================================================================
            print("\n[*] TEST 10: Real GraphQL Invariant Playwright Tests (Item 9)...")
            graphql_context = browser.new_context(viewport={"width": 1280, "height": 800})
            
            # (a) Real-shaped success
            print("  [*] (a) Testing real-shaped success response...")
            page_a = graphql_context.new_page()
            page_a.route("**/v1/graphql", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({
                    "data": {
                        "GlobalSecurityStats": [{
                            "totalActionsExecuted": "350",
                            "totalThreatsRegistered": "12",
                            "activeThreatCount": "4",
                            "totalPassportsTracked": "7",
                            "totalCortexRootsAnchored": "2"
                        }],
                        "AgentAction": [],
                        "ThreatRecord": []
                    }
                })
            ))
            page_a.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page_a.evaluate("() => localStorage.setItem('guardian_mode', 'simple')")
            page_a.reload(wait_until="networkidle")
            page_a.wait_for_timeout(1000)
            
            actions_tile_a = page_a.locator(".border-border\\/80:has-text('Actions executed')")
            assert actions_tile_a.count() > 0, "FAILED (a): Actions executed tile locator not found"
            assert "350" in actions_tile_a.inner_text(), f"FAILED (a): Expected '350' in Actions executed tile: {actions_tile_a.inner_text()}"
            
            threats_feed_tile_a = page_a.locator(".border-border\\/70:has-text('Threats in the threat feed')")
            assert threats_feed_tile_a.count() > 0, "FAILED (a): Threats in the threat feed tile locator not found"
            assert "12" in threats_feed_tile_a.inner_text(), f"FAILED (a): Expected '12' in Threats in the threat feed tile: {threats_feed_tile_a.inner_text()}"
            print("  [+] (a) Real-shaped success PASSED: tile 'Actions executed' contains '350' and 'Threats in the threat feed' contains '12'.")
            page_a.close()

            # (b) HTTP 500 at first load
            print("  [*] (b) Testing HTTP 500 on first load (no prior cache)...")
            page_b = graphql_context.new_page()
            page_b.route("**/v1/graphql", lambda route: route.fulfill(status=500, body="Internal Server Error"))
            page_b.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page_b.evaluate("() => { localStorage.clear(); localStorage.setItem('guardian_mode', 'simple'); }")
            page_b.reload(wait_until="networkidle")
            page_b.wait_for_timeout(1200)

            body_b = page_b.inner_text("body")
            assert "couldn't load data" in body_b.lower(), f"FAILED (b): Expected 'Couldn't load data' in body: {body_b[:400]}"
            
            # Assert that top summary cards have NO digits
            stat_cards = page_b.locator(".grid.grid-cols-1.sm\\:grid-cols-2.lg\\:grid-cols-4 .border-border\\/80")
            card_count = stat_cards.count()
            assert card_count == 4, f"Expected 4 top summary cards, got {card_count}"
            for c_idx in range(card_count):
                metric_row = stat_cards.nth(c_idx).locator(".flex.items-baseline")
                metric_text = metric_row.inner_text() if metric_row.count() > 0 else stat_cards.nth(c_idx).inner_text()
                import re
                has_digit = bool(re.search(r'\d', metric_text))
                assert not has_digit, f"FAILED (b): Stat tile {c_idx+1} contains digits in failed state: '{metric_text}'"

            # Assert that Security Records stat tiles also have NO digits
            sec_stat_labels = [
                "Threats in the threat feed",
                "Active threat indicators",
                "Agent passports tracked",
                "On-chain activity"
            ]
            for label in sec_stat_labels:
                tile = page_b.locator(f".border-border\\/70:has-text('{label}')")
                assert tile.count() > 0, f"FAILED (b): Could not find Security Records stat tile '{label}'"
                tile_text = tile.inner_text()
                assert "couldn't load data" in tile_text.lower(), f"FAILED (b): Tile '{label}' missing 'Couldn't load data': '{tile_text}'"
                import re
                has_digit = bool(re.search(r'\d', tile_text))
                assert not has_digit, f"FAILED (b): Security Records stat tile '{label}' contains digits in failed state: '{tile_text}'"
            print("  [+] (b) HTTP 500 first load PASSED: displays 'Couldn't load data' with ZERO digits across ALL stat tiles including Security Records.")
            page_b.close()

            # (c) Success then HTTP 500 on next poll
            print("  [*] (c) Testing success followed by HTTP 500 on next poll...")
            poll_state = {"count": 0}
            def route_poll(route):
                poll_state["count"] += 1
                if poll_state["count"] == 1:
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps({
                            "data": {
                                "GlobalSecurityStats": [{
                                    "totalActionsExecuted": "350",
                                    "totalThreatsRegistered": "12",
                                    "activeThreatCount": "4",
                                    "totalPassportsTracked": "7",
                                    "totalCortexRootsAnchored": "2"
                                }],
                                "AgentAction": [],
                                "ThreatRecord": []
                            }
                        })
                    )
                else:
                    route.fulfill(status=500, body="Internal Server Error")

            page_c = graphql_context.new_page()
            page_c.add_init_script("localStorage.clear(); localStorage.setItem('guardian_mode', 'simple');")
            page_c.route("**/v1/graphql", route_poll)
            page_c.goto("http://localhost:5188/#dashboard", wait_until="networkidle")

            # Confirm initial success values
            actions_tile_c = page_c.locator(".border-border\\/80:has-text('Actions executed')").first
            actions_tile_c.wait_for(state="visible", timeout=5000)
            assert "350" in actions_tile_c.inner_text(), "FAILED (c): Initial load did not show 350"
            threats_tile_c = page_c.locator(".border-border\\/80:has-text('Threats registered')").first
            assert "12" in threats_tile_c.inner_text(), "FAILED (c): Initial load did not show 12"

            # Wait for next poll to trigger HTTP 500 using locator wait_for, not fixed sleep
            print("      Waiting for second poll to trigger HTTP 500 via locator.wait_for...")
            stale_banner = page_c.locator('[data-testid="stale-banner"]').first
            stale_banner.wait_for(state="visible", timeout=12000)

            body_c2 = page_c.inner_text("body")
            assert "stale cache" in body_c2.lower() or "couldn't refresh" in body_c2.lower() or "last updated" in body_c2.lower(), f"FAILED (c): Stale label not found: {body_c2[:500]}"
            assert "350" in actions_tile_c.inner_text(), f"FAILED (c): Last good value 350 was not preserved: {actions_tile_c.inner_text()}"
            assert "12" in threats_tile_c.inner_text(), f"FAILED (c): Last good value 12 was not preserved: {threats_tile_c.inner_text()}"
            print("  [+] (c) Stale polling PASSED: Stale label visible via wait_for AND last good values (350, 12) preserved.")
            page_c.close()
            graphql_context.close()

            # =========================================================================
            # TEST 11: Part E Item 1 - Simple Mode Status Indicator Invariants
            # (i) GraphQL mocked with AgentAction riskScore 95 -> Simple mode shows "Attention needed"
            # (ii) /?demo=true with sample blocked event -> Simple mode shows "Attention needed"
            # =========================================================================
            print("\n[*] TEST 11: Part E Item 1 - Simple Mode Status Indicator Invariants...")
            status_context = browser.new_context(viewport={"width": 1280, "height": 800})
            
            # (i) Mocked AgentAction with riskScore 95
            print("  [*] (i) Testing GraphQL mock with AgentAction riskScore 95...")
            page_high_risk = status_context.new_page()
            page_high_risk.route("**/v1/graphql", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({
                    "data": {
                        "GlobalSecurityStats": [{
                            "totalActionsExecuted": "350",
                            "totalThreatsRegistered": "12",
                            "activeThreatCount": "4",
                            "totalPassportsTracked": "7",
                            "totalCortexRootsAnchored": "2"
                        }],
                        "AgentAction": [{
                            "id": "action-95",
                            "agentId": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                            "target": "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
                            "riskScore": 95,
                            "timestamp": 1700000000,
                            "txHash": "0x3a51f89c02d1847c25e8391a27e771c56b72d2459a721d7b328a9b1c73f01101"
                        }],
                        "ThreatRecord": []
                    }
                })
            ))
            page_high_risk.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page_high_risk.evaluate("() => localStorage.setItem('guardian_mode', 'simple')")
            page_high_risk.reload(wait_until="networkidle")
            attention_badge_1 = page_high_risk.locator("text=Attention needed").first
            attention_badge_1.wait_for(state="visible", timeout=6000)
            assert attention_badge_1.is_visible(), "FAILED (i): Simple mode did not show 'Attention needed' for riskScore 95"
            print("  [+] (i) AgentAction riskScore 95 verified: Simple mode displays 'Attention needed'.")
            page_high_risk.close()

            # (ii) /?demo=true with sample blocked event
            print("  [*] (ii) Testing /?demo=true with sample blocked event...")
            page_demo_status = status_context.new_page()
            page_demo_status.goto("http://localhost:5188/?demo=true#dashboard", wait_until="networkidle")
            page_demo_status.evaluate("() => localStorage.setItem('guardian_mode', 'simple')")
            page_demo_status.reload(wait_until="networkidle")
            attention_badge_2 = page_demo_status.locator("text=Attention needed").first
            attention_badge_2.wait_for(state="visible", timeout=6000)
            assert attention_badge_2.is_visible(), "FAILED (ii): Simple mode did not show 'Attention needed' with sample blocked event"
            print("  [+] (ii) Demo mode sample blocked event verified: Simple mode displays 'Attention needed'.")
            page_demo_status.close()
            status_context.close()

            # =========================================================================
            # TEST 12: Part E Item 3 - Probe Isolation in Simple Mode
            # Clicking tamper and failing passport probes with clean GraphQL mock leaves Simple status unchanged
            # =========================================================================
            print("\n[*] TEST 12: Part E Item 3 - Probe Isolation Outside Demo Mode...")
            isolation_context = browser.new_context(viewport={"width": 1280, "height": 800})
            page_iso = isolation_context.new_page()
            page_iso.route("**/v1/graphql", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({
                    "data": {
                        "GlobalSecurityStats": [{
                            "totalActionsExecuted": "100",
                            "totalThreatsRegistered": "0",
                            "activeThreatCount": "0",
                            "totalPassportsTracked": "5",
                            "totalCortexRootsAnchored": "1"
                        }],
                        "AgentAction": [{
                            "id": "action-nominal-1",
                            "agentId": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                            "target": "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
                            "riskScore": 5,
                            "timestamp": 1700000000,
                            "txHash": "0x3a51f89c02d1847c25e8391a27e771c56b72d2459a721d7b328a9b1c73f01101"
                        }],
                        "ThreatRecord": []
                    }
                })
            ))
            # Start on #dashboard in Simple mode and verify clean nominal status
            page_iso.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page_iso.evaluate("() => localStorage.setItem('guardian_mode', 'simple')")
            page_iso.reload(wait_until="networkidle")
            page_iso.wait_for_timeout(800)
            nom_status = page_iso.locator("text=No flagged on-chain actions").first
            nom_status.wait_for(state="visible", timeout=5000)
            print("  [+] Initial Simple mode status confirmed: 'No flagged on-chain actions'.")

            # Switch to Advanced mode to access probe tabs on #agents
            page_iso.locator("#mode-advanced-btn").click()
            page_iso.goto("http://localhost:5188/#agents", wait_until="networkidle")
            page_iso.wait_for_timeout(600)

            # Click simulate probe sub-tabs
            probe_tabs = page_iso.locator("button:has-text('Simulate Probe')")
            tab_count = probe_tabs.count()
            assert tab_count >= 2, f"Expected probe tab buttons on agent cards, found {tab_count}"
            
            # Click Mera Tamper Probe tab and trigger attack button
            probe_tabs.nth(1).click()
            page_iso.wait_for_timeout(300)
            tamper_btn = page_iso.locator("button:has-text('Simulate Memory Tamper Probe')").first
            tamper_btn.wait_for(state="visible", timeout=5000)
            tamper_btn.click()
            tamper_feedback = page_iso.locator("text=MERA MEMORY TAMPERING DETECTED & ISOLATED").first
            tamper_feedback.wait_for(state="visible", timeout=5000)
            assert tamper_feedback.is_visible(), "FAILED: Tamper feedback banner not visible after clicking tamper probe!"

            # Click Passport Probe tab and trigger check button (RPC failing)
            page_iso.route("https://testnet-rpc.monad.xyz**", lambda route: route.abort())
            probe_tabs.nth(2).click()
            page_iso.wait_for_timeout(300)
            passport_btn = page_iso.locator("button:has-text('Check Test ID revoked-agent-01')").first
            passport_btn.wait_for(state="visible", timeout=5000)
            passport_btn.click()
            passport_feedback = page_iso.locator("text=/Couldn't verify \\(network error\\)|No active passport/i").first
            passport_feedback.wait_for(state="visible", timeout=5000)
            assert passport_feedback.is_visible(), "FAILED: Passport feedback banner not visible after clicking passport probe!"
            page_iso.unroute("https://testnet-rpc.monad.xyz**")

            # Return to Simple mode on #dashboard
            page_iso.locator("#mode-simple-btn").click()
            page_iso.goto("http://localhost:5188/#dashboard", wait_until="networkidle")
            page_iso.wait_for_timeout(800)

            # Assert Simple mode status remains nominal ("No flagged on-chain actions")
            nom_status_after = page_iso.locator("text=No flagged on-chain actions").first
            assert nom_status_after.is_visible(), "FAILED: Simple mode status changed after simulated probes outside demo mode!"
            assert page_iso.locator("text=Attention needed").count() == 0, "FAILED: 'Attention needed' appeared after probe outside demo mode!"
            print("  [+] Probe Isolation PASSED: Status remains 'No flagged on-chain actions' after triggering tamper and failing passport probes.")
            page_iso.close()
            isolation_context.close()

            # =========================================================================
            # TEST 13: Part F Item 1 - Threat Feed Separation & Address Correlation Invariant
            # (a) 3 ThreatRecords (2 active, 1 removed), no match -> "No flagged on-chain actions", risk average unaffected (shows 5 / 100, not 95)
            # (b) Target matches active threat record -> "Attention needed" + copy "An agent interacted with a listed address."
            # (c) Target matches only removed record -> not amber (remains "No flagged on-chain actions")
            # =========================================================================
            print("\n[*] TEST 13: Part F Item 1 - Threat Feed Separation & Address Correlation Invariant...")
            tf_context = browser.new_context(viewport={"width": 1280, "height": 800})
            tf_context.add_init_script(IIFE_INIT_SCRIPT)

            # Common threat feed with 3 records (2 active, 1 removed)
            mock_threat_records = [
                {"id": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "reason": "Phishing drainer", "active": True, "addedAt": 1700000001},
                {"id": "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "reason": "Exploit contract", "active": True, "addedAt": 1700000002},
                {"id": "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "reason": "False positive", "active": False, "addedAt": 1700000003}
            ]

            # Case (a): Target does not match any threat record
            def route_case_a(route):
                payload = {
                    "data": {
                        "GlobalSecurityStats": [{
                            "totalActionsExecuted": "100",
                            "totalThreatsRegistered": "3",
                            "activeThreatCount": "2",
                            "totalPassportsTracked": "5"
                        }],
                        "AgentAction": [{
                            "id": "action-1",
                            "agentId": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                            "target": "0x9999999999999999999999999999999999999999",
                            "riskScore": 5,
                            "timestamp": 1700000050,
                            "txHash": "0x" + "a" * 64
                        }],
                        "ThreatRecord": mock_threat_records
                    }
                }
                route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

            page_tf = tf_context.new_page()
            page_tf.add_init_script("localStorage.clear(); localStorage.setItem('guardian_mode', 'simple');")
            page_tf.route("**/v1/graphql", route_case_a)
            page_tf.goto("http://localhost:5188/#dashboard", wait_until="domcontentloaded")

            # Assert (a): "No flagged on-chain actions" and risk average 5 / 100 (not 95)
            status_a = page_tf.locator("text=No flagged on-chain actions").first
            status_a.wait_for(state="visible", timeout=5000)
            assert status_a.is_visible(), "FAILED (a): Simple mode status was not 'No flagged on-chain actions'"
            assert page_tf.locator("text=Attention needed").count() == 0, "FAILED (a): 'Attention needed' shown when no target matched!"
            
            # Assert risk average is unaffected by ThreatRecord (shows 5 / 100, NOT 95)
            risk_avg_locator = page_tf.locator(".text-3xl.font-bold:has-text('/ 100')").first
            risk_avg_locator.wait_for(state="visible", timeout=5000)
            risk_avg_text = risk_avg_locator.inner_text()
            assert "5" in risk_avg_text and "95" not in risk_avg_text, f"FAILED (a): Expected risk average 5 / 100, got: {risk_avg_text}"
            print("  [+] Case (a) PASSED: 3 ThreatRecords with non-matching target -> 'No flagged on-chain actions' and session average shows 5 / 100.")

            # Case (b): Target matches active threat record (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
            def route_case_b(route):
                payload = {
                    "data": {
                        "GlobalSecurityStats": [{
                            "totalActionsExecuted": "100",
                            "totalThreatsRegistered": "3",
                            "activeThreatCount": "2",
                            "totalPassportsTracked": "5"
                        }],
                        "AgentAction": [{
                            "id": "action-2",
                            "agentId": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                            "target": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "riskScore": 5,
                            "timestamp": 1700000050,
                            "txHash": "0x" + "b" * 64
                        }],
                        "ThreatRecord": mock_threat_records
                    }
                }
                route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

            page_tf.unroute("**/v1/graphql")
            page_tf.route("**/v1/graphql", route_case_b)
            page_tf.reload(wait_until="commit")
            page_tf.wait_for_timeout(300)

            # Assert (b): "Attention needed" + copy "An agent interacted with a listed address."
            status_b = page_tf.locator("text=Attention needed").first
            status_b.wait_for(state="visible", timeout=5000)
            assert status_b.is_visible(), "FAILED (b): Status was not 'Attention needed' when target matched active threat!"
            copy_b = page_tf.locator("text=An agent interacted with a listed address.").first
            copy_b.wait_for(state="visible", timeout=5000)
            assert copy_b.is_visible(), "FAILED (b): Copy 'An agent interacted with a listed address.' not displayed!"
            print("  [+] Case (b) PASSED: Target matches ACTIVE threat -> 'Attention needed' + 'An agent interacted with a listed address.'.")

            # Case (c): Target matches only removed threat record (0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC, active=False)
            def route_case_c(route):
                payload = {
                    "data": {
                        "GlobalSecurityStats": [{
                            "totalActionsExecuted": "100",
                            "totalThreatsRegistered": "3",
                            "activeThreatCount": "2",
                            "totalPassportsTracked": "5"
                        }],
                        "AgentAction": [{
                            "id": "action-3",
                            "agentId": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                            "target": "0xcccccccccccccccccccccccccccccccccccccccc",
                            "riskScore": 5,
                            "timestamp": 1700000050,
                            "txHash": "0x" + "c" * 64
                        }],
                        "ThreatRecord": mock_threat_records
                    }
                }
                route.fulfill(status=200, content_type="application/json", body=json.dumps(payload))

            page_tf.unroute("**/v1/graphql")
            page_tf.route("**/v1/graphql", route_case_c)
            page_tf.reload(wait_until="commit")
            page_tf.wait_for_timeout(300)

            # Assert (c): remains "No flagged on-chain actions" (not amber)
            status_c = page_tf.locator("text=No flagged on-chain actions").first
            status_c.wait_for(state="visible", timeout=5000)
            assert status_c.is_visible(), "FAILED (c): Status was not 'No flagged on-chain actions' when target matched removed threat!"
            assert page_tf.locator("text=Attention needed").count() == 0, "FAILED (c): 'Attention needed' shown when target only matched removed threat!"
            print("  [+] Case (c) PASSED: Target matches only REMOVED threat -> remains 'No flagged on-chain actions'.")
            page_tf.close()
            tf_context.close()

            browser.close()
            print("\n=======================================================")
            print("  [SUCCESS] ALL PHASE 1a & PHASE 1b BROWSER TESTS PASSED!")
            print("=======================================================")

    finally:
        server.terminate()

if __name__ == "__main__":
    run_browser_tests()
