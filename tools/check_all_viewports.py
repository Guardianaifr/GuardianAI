import os
from playwright.sync_api import sync_playwright

WEBSITE_DIR = os.path.abspath('website')

with sync_playwright() as p:
    browser = p.chromium.launch()
    
    for width in [320, 360, 375, 414, 768, 1024, 1280, 1440, 1920]:
        print(f"\n================ VIEWPORT {width}px ================")
        for page_name in ['index.html', 'pricing.html', 'how-it-works.html', 'proof.html', 'docs.html']:
            context = browser.new_context(viewport={"width": width, "height": 800})
            page = context.new_page()
            url = "file:///" + os.path.join(WEBSITE_DIR, page_name).replace('\\', '/')
            page.goto(url)
            page.wait_for_load_state("networkidle")
            
            cw = page.evaluate("() => document.documentElement.clientWidth")
            sw = page.evaluate("() => document.documentElement.scrollWidth")
            is_overflow = sw > cw + 1
            print(f"  {page_name:<18} cw={cw} sw={sw} overflow={is_overflow}")
            context.close()
            
    browser.close()
