import os
import sys
from playwright.sync_api import sync_playwright

WEBSITE_DIR = os.path.abspath('website')

def test_deep():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        
        # Test 320px viewport for all pages (smallest mobile)
        pages = ['index.html', 'how-it-works.html', 'pricing.html', 'proof.html', 'docs.html']
        print("=== TESTING 320px VIEWPORT ===")
        for pg in pages:
            url = f"file:///{os.path.join(WEBSITE_DIR, pg).replace('\\', '/')}"
            page = browser.new_page(viewport={"width": 320, "height": 568})
            page.goto(url, wait_until="networkidle")
            overflow = page.evaluate("""() => {
                const doc = document.documentElement;
                const body = document.body;
                const sw = Math.max(doc.scrollWidth, body.scrollWidth);
                const cw = doc.clientWidth;
                return { isOverflow: sw > cw + 1, sw, cw };
            }""")
            print(f"  {pg:18} cw={overflow['cw']} sw={overflow['sw']} overflow={overflow['isOverflow']}")
            assert not overflow['isOverflow'], f"Horizontal overflow detected on {pg} at 320px: sw={overflow['sw']} > cw={overflow['cw']}"
            page.close()
            
        # Test docs.html interactions
        print("\n=== TESTING DOCS.HTML ===")
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'docs.html').replace('\\', '/')}")
        
        # Search modal
        page.keyboard.press("Control+k")
        page.wait_for_timeout(200)
        is_search_open = page.locator("#docs-search-modal").evaluate("el => el.classList.contains('open')")
        print("  Docs search opens via Ctrl+K:", is_search_open)
        
        page.fill("#docs-search-input", "firewall")
        page.wait_for_timeout(200)
        cnt = page.locator("#docs-search-results li").count()
        print("  Search results for 'firewall':", cnt)
        
        page.keyboard.press("Escape")
        page.wait_for_timeout(200)
        is_search_closed = page.locator("#docs-search-modal").evaluate("el => !el.classList.contains('open')")
        print("  Docs search closes via Esc:", is_search_closed)
        
        # Code tabs in docs
        tabs = page.locator(".docs-tab")
        print(f"  Docs tabs found: {tabs.count()}")
        if tabs.count() > 1:
            tabs.nth(1).click()
            page.wait_for_timeout(100)
            active_tab = tabs.nth(1).evaluate("el => el.classList.contains('active')")
            print("  Docs tab switch:", active_tab)
            
        # Copy button in docs
        copy_btns = page.locator(".docs-copy-btn")
        print(f"  Docs copy buttons found: {copy_btns.count()}")
        if copy_btns.count() > 0:
            copy_btns.first.click()
            page.wait_for_timeout(100)
            btn_text = copy_btns.first.inner_text()
            print("  Docs copy button clicked, text:", repr(btn_text))
            
        page.close()
        context.close()
        
        # Mobile docs sidebar
        page = browser.new_page(viewport={"width": 375, "height": 667})
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'docs.html').replace('\\', '/')}")
        toggle = page.locator("#docs-sidebar-toggle")
        print("  Docs sidebar toggle visible on mobile:", toggle.is_visible())
        toggle.click()
        page.wait_for_timeout(200)
        sb_open = page.locator("#docs-sidebar").evaluate("el => el.classList.contains('open')")
        print("  Docs sidebar opened:", sb_open)
        page.close()
        
        # Test how-it-works.html tabs & copy
        print("\n=== TESTING HOW-IT-WORKS.HTML ===")
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'how-it-works.html').replace('\\', '/')}")
        hiw_tabs = page.locator(".code-tab-btn")
        print(f"  HIW code tabs count: {hiw_tabs.count()}")
        if hiw_tabs.count() > 1:
            hiw_tabs.nth(1).click()
            page.wait_for_timeout(100)
            active_hiw = page.locator("#hiw-proxy").evaluate("el => el.classList.contains('active')")
            print("  HIW tab switched to Proxy:", active_hiw)
            
        hiw_copy = page.locator(".copy-btn")
        if hiw_copy.count() > 0:
            hiw_copy.first.click()
            page.wait_for_timeout(100)
            print("  HIW copy button text:", repr(hiw_copy.first.inner_text()))
        page.close()

        # Test pricing.html switcher
        print("\n=== TESTING PRICING.HTML ===")
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'pricing.html').replace('\\', '/')}")
        p_monthly = page.locator(".pricing-switch-btn[data-billing='monthly']")
        if p_monthly.count() > 0:
            p_monthly.click()
            page.wait_for_timeout(100)
            starter_txt = page.locator("#price-starter").inner_text()
            print("  Pricing page monthly starter text:", repr(starter_txt))
        page.close()

        # Test index.html edge cases:
        print("\n=== TESTING INDEX.HTML EDGE CASES ===")
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto(f"file:///{os.path.join(WEBSITE_DIR, 'index.html').replace('\\', '/')}")
        
        # 1. Custom Payload chip click
        custom_chip = page.locator(".scenario-chip.custom")
        print(f"  Custom payload chip exists: {custom_chip.count() > 0}")
        if custom_chip.count() > 0:
            custom_chip.click()
            page.wait_for_timeout(100)
            inp_val = page.locator("#studio-input").input_value()
            print(f"  Studio input after custom chip: {repr(inp_val)}")
            # Try clicking scan with empty input
            page.locator("#studio-scan-btn").click()
            page.wait_for_timeout(200)
            verdict_text = page.locator("#studio-verdict").inner_text()
            print(f"  Verdict text with empty input: {repr(verdict_text)}")
            
        # 2. Test 4-stage pipeline card click (stage detail drawer)
        stage_card = page.locator("#stage-1")
        stage_card.click()
        page.wait_for_timeout(100)
        drawer_open = page.locator("#stage-detail-drawer").evaluate("el => el.classList.contains('open')")
        drawer_text = page.locator("#stage-detail-drawer").inner_text().replace('\n', ' ')
        print(f"  Stage 1 clicked -> drawer open: {drawer_open}, text: {drawer_text[:60]}")
        
        # 3. Test Copy Forensic JSON button
        chips = page.locator(".scenario-chip")
        chips.first.click()
        page.locator("#studio-scan-btn").click()
        page.wait_for_timeout(1000)
        copy_forensic = page.locator("#copy-forensic-btn")
        print(f"  Copy forensic btn visible: {copy_forensic.is_visible()}")
        if copy_forensic.is_visible():
            copy_forensic.click()
            page.wait_for_timeout(100)
            print(f"  Copy forensic btn text: {copy_forensic.inner_text()}")
            
        page.close()
        browser.close()

if __name__ == '__main__':
    test_deep()
