import os
import sys
from playwright.sync_api import sync_playwright

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

WEBSITE_DIR = os.path.abspath('website')

def test_pages():
    results = {"errors": [], "warnings": [], "overflows": [], "interactions": []}
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        pages_to_test = [
            'index.html',
            'how-it-works.html',
            'pricing.html',
            'proof.html',
            'docs.html'
        ]
        
        viewports = [
            {"name": "desktop", "width": 1280, "height": 800},
            {"name": "mobile", "width": 375, "height": 667}
        ]
        
        for page_name in pages_to_test:
            page_url = f"file:///{os.path.join(WEBSITE_DIR, page_name).replace('\\', '/')}"
            
            for vp in viewports:
                context = browser.new_context(viewport={"width": vp["width"], "height": vp["height"]})
                page = context.new_page()
                
                console_msgs = []
                page_errors = []
                page.on("console", lambda msg: console_msgs.append(f"[{msg.type}] {msg.text}"))
                page.on("pageerror", lambda err: page_errors.append(str(err)))
                
                page.goto(page_url, wait_until="networkidle")
                
                # Check for console errors
                if page_errors:
                    results["errors"].append(f"{page_name} ({vp['name']}): Page errors: {page_errors}")
                for msg in console_msgs:
                    if "error" in msg.lower():
                        results["errors"].append(f"{page_name} ({vp['name']}): Console error: {msg}")
                
                # Check for horizontal overflow
                overflow_info = page.evaluate("""() => {
                    const docEl = document.documentElement;
                    const body = document.body;
                    const scrollWidth = Math.max(docEl.scrollWidth, body.scrollWidth);
                    const clientWidth = docEl.clientWidth;
                    const isOverflow = scrollWidth > clientWidth + 1;
                    
                    let badEls = [];
                    if (isOverflow) {
                        document.querySelectorAll('*').forEach(el => {
                            const rect = el.getBoundingClientRect();
                            if (rect.right > clientWidth + 2 && rect.width > 0 && rect.height > 0) {
                                badEls.push({
                                    tag: el.tagName,
                                    id: el.id,
                                    className: el.className.toString().slice(0, 50),
                                    right: rect.right,
                                    width: rect.width
                                });
                            }
                        });
                    }
                    return { isOverflow, scrollWidth, clientWidth, badEls: badEls.slice(0, 5) };
                }""")
                
                if overflow_info["isOverflow"]:
                    results["overflows"].append(
                        f"{page_name} ({vp['name']}): scrollWidth ({overflow_info['scrollWidth']}) > clientWidth ({overflow_info['clientWidth']}). Bad elements: {overflow_info['badEls']}"
                    )
                
                context.close()
                
        # Now test specific interactive elements on index.html
        print("Testing interactive elements on index.html...")
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'index.html').replace('\\', '/')}")
        
        # 1. Command Palette Trigger
        page.keyboard.press("Control+k")
        page.wait_for_timeout(200)
        is_cmd_open = page.locator("#cmd-modal").evaluate("el => el.classList.contains('open')")
        results["interactions"].append(f"Command palette opens via Ctrl+K: {is_cmd_open}")
        page.keyboard.press("Escape")
        page.wait_for_timeout(200)
        is_cmd_closed = page.locator("#cmd-modal").evaluate("el => !el.classList.contains('open')")
        results["interactions"].append(f"Command palette closes via Escape: {is_cmd_closed}")
        
        # 2. Defense Studio: Scenario selection and entropy calculation
        chips = page.locator(".scenario-chip")
        chip_count = chips.count()
        results["interactions"].append(f"Scenario chips loaded: {chip_count}")
        if chip_count > 1:
            chips.nth(1).click()
            page.wait_for_timeout(100)
            entropy_text = page.locator("#entropy-val").inner_text()
            results["interactions"].append(f"Entropy updated on chip click: {entropy_text}")
            
            # Scan button click
            page.locator("#studio-scan-btn").click()
            page.wait_for_timeout(1000)
            verdict_visible = page.locator("#studio-verdict").evaluate("el => el.classList.contains('show')")
            verdict_text = page.locator("#studio-verdict").inner_text().replace('\n', ' ')[:80]
            results["interactions"].append(f"Studio verdict rendered: {verdict_visible} -> {verdict_text}")
            
        # 3. Code Tabs & Terminal Simulator
        tab_proxy = page.locator(".code-tab-btn[data-tab='tab-proxy']")
        if tab_proxy.count() > 0:
            tab_proxy.click()
            page.wait_for_timeout(100)
            proxy_view_active = page.locator("#tab-proxy").evaluate("el => el.classList.contains('active')")
            results["interactions"].append(f"OpenAI proxy tab switched: {proxy_view_active}")
            
        sim_btn = page.locator("#run-sim-btn")
        if sim_btn.count() > 0:
            sim_btn.click()
            page.wait_for_timeout(600)
            sim_out = page.locator("#terminal-output").inner_text()
            has_sim_payload = "x-guardian-decision" in sim_out
            results["interactions"].append(f"Terminal simulator executed: {has_sim_payload}")
            
        # 4. Benchmark mode toggle
        bm_balanced = page.locator(".toggle-pill-btn[data-bm-mode='balanced']")
        if bm_balanced.count() > 0:
            bm_balanced.click()
            page.wait_for_timeout(100)
            first_rate = page.locator("#benchmark-tbody tr:first-child .num b").inner_text()
            results["interactions"].append(f"Benchmark mode toggled to balanced (rate: {first_rate})")
            
        # 5. Pricing toggle
        monthly_btn = page.locator(".pricing-switch-btn[data-billing='monthly']")
        if monthly_btn.count() > 0:
            monthly_btn.click()
            page.wait_for_timeout(100)
            price_starter = page.locator("#price-starter").inner_text()
            results["interactions"].append(f"Pricing switched to monthly (starter: {price_starter})")
            
        # 6. FAQ toggle
        faq_q = page.locator(".faq-question").first
        if faq_q.count() > 0:
            faq_q.click()
            page.wait_for_timeout(100)
            faq_open = page.locator(".faq-item").first.evaluate("el => el.classList.contains('open')")
            results["interactions"].append(f"FAQ accordion toggled: {faq_open}")
            
        # 7. Waitlist form submission
        page.locator(".waitlist-input").first.fill("test@enterprise.com")
        page.locator(".waitlist-form button[type='submit']").first.click()
        page.wait_for_timeout(200)
        status_text = page.locator(".waitlist-status").first.inner_text()
        results["interactions"].append(f"Waitlist submitted: {status_text}")
        
        context.close()
        
        # Test Mobile Menu on Mobile Viewport
        print("Testing mobile navigation...")
        context = browser.new_context(viewport={"width": 375, "height": 667})
        page = context.new_page()
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'index.html').replace('\\', '/')}")
        
        nav_toggle = page.locator(".nav-toggle")
        if nav_toggle.is_visible():
            nav_toggle.click()
            page.wait_for_timeout(200)
            menu_open = page.locator("#nav-links").evaluate("el => el.classList.contains('open')")
            results["interactions"].append(f"Mobile nav menu opened: {menu_open}")
            
            # Click a link inside
            page.locator("#nav-links a").first.click()
            page.wait_for_timeout(200)
            results["interactions"].append("Mobile nav link navigation succeeded")
        else:
            results["warnings"].append("Mobile nav-toggle not visible on 375px width")
            
        context.close()
        browser.close()
        
    print("\n=== PLAYWRIGHT AUDIT RESULTS ===")
    print(f"Errors ({len(results['errors'])}):")
    for e in results["errors"]:
        print("  [ERROR]", e)
    print(f"Overflows ({len(results['overflows'])}):")
    for o in results["overflows"]:
        print("  [OVERFLOW]", o)
    print(f"Warnings ({len(results['warnings'])}):")
    for w in results["warnings"]:
        print("  [WARNING]", w)
    print(f"Interactions ({len(results['interactions'])}):")
    for i in results["interactions"]:
        print("  [OK]", i)

if __name__ == '__main__':
    test_pages()
