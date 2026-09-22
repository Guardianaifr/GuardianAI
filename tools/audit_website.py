import os
import re
import sys
from glob import glob

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def audit():
    print("=== GUARDIAN WEBSITE AUDIT ===")
    
    # 1. Assets check
    assets = glob('website/assets/*')
    print(f"Assets found ({len(assets)}): {[os.path.basename(a) for a in assets]}")

    # 2. HTML Files check
    html_files = sorted(glob('website/*.html'))
    print(f"HTML files found ({len(html_files)}): {[os.path.basename(h) for h in html_files]}")

    ids = {}
    all_links = []
    
    for h in html_files:
        base = os.path.basename(h)
        with open(h, 'r', encoding='utf-8') as f:
            content = f.read()
        
        found_ids = set(re.findall(r'id=["\']([^"\']+)["\']', content))
        ids[base] = found_ids
        
        # Check title & meta
        title_match = re.search(r'<title>(.*?)</title>', content)
        title = title_match.group(1) if title_match else "MISSING TITLE"
        
        # Check unclosed tags (basic stack check)
        void_tags = {'meta', 'link', 'img', 'br', 'hr', 'input', 'source', 'path', 'circle', 'rect', 'line', 'polyline', 'polygon'}
        tag_tokens = re.findall(r'<(/?[a-zA-Z0-9\-]+)[^>]*?(/?)>', content)
        stack = []
        for tag, self_closing in tag_tokens:
            tag_lower = tag.lower()
            if self_closing == '/' or tag_lower in void_tags:
                continue
            if tag_lower.startswith('/'):
                closing = tag_lower[1:]
                if stack and stack[-1] == closing:
                    stack.pop()
                else:
                    # Unmatched closing or mismatch
                    pass
            else:
                stack.append(tag_lower)
        print(f"{base}: Title='{title[:40]}...', Unclosed stack count={len(stack)} (top 5: {stack[-5:] if stack else []})")

        # Extract links
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', content)
        for hr in hrefs:
            all_links.append((base, hr))

    # Check broken links
    print("\n--- LINK ANALYSIS ---")
    broken = []
    for source, href in all_links:
        if href.startswith(('http://', 'https://', 'mailto:', 'tel:')):
            continue
        if href == '' or href == '#':
            # Empty or bare anchor
            broken.append((source, href, "Empty or bare hash link"))
            continue
        if href.startswith('#'):
            target_id = href[1:]
            if target_id not in ids[source]:
                broken.append((source, href, f"Anchor #{target_id} not found in {source}"))
        elif '#' in href:
            path, target_id = href.split('#', 1)
            # Normalize path
            norm_path = path.lstrip('/')
            if not norm_path.endswith('.html') and norm_path in [h.replace('.html', '') for h in ids]:
                norm_path += '.html'
            if norm_path not in ids:
                broken.append((source, href, f"Target page '{norm_path}' not found"))
            elif target_id not in ids[norm_path]:
                broken.append((source, href, f"Anchor #{target_id} not found in {norm_path}"))
        else:
            norm_path = href.lstrip('/')
            clean_path = norm_path.split('?')[0]
            if clean_path in ids or os.path.exists(os.path.join('website', clean_path)):
                pass
            elif clean_path + '.html' in ids:
                broken.append((source, href, f"Missing .html extension: should be {clean_path}.html"))
            else:
                broken.append((source, href, f"Resource not found: {href}"))

    print(f"Total links: {len(all_links)}, Broken: {len(broken)}")
    for b in broken[:20]:
        print(f"  [BROKEN] in {b[0]}: {b[1]} -> {b[2]}")
    if len(broken) > 20:
        print(f"  ... and {len(broken)-20} more.")

    # 3. CSS Audit
    print("\n--- CSS AUDIT ---")
    for css_file in ['website/css/style.css', 'website/css/docs.css']:
        if os.path.exists(css_file):
            with open(css_file, 'r', encoding='utf-8') as f:
                c = f.read()
            o_brace = c.count('{')
            c_brace = c.count('}')
            print(f"{css_file}: {len(c)} bytes, {{ {o_brace} vs }} {c_brace}")

    # 4. JS Audit
    print("\n--- JS AUDIT ---")
    js_file = 'website/js/main.js'
    if os.path.exists(js_file):
        with open(js_file, 'r', encoding='utf-8') as f:
            j = f.read()
        print(f"{js_file}: {len(j)} bytes, lines: {j.count(chr(10))}")

if __name__ == '__main__':
    audit()
