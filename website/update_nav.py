import os

website_dir = r"f:/Saas/guardianai-basic-launch/website"

files = ["index.html", "how-it-works.html", "pricing.html", "proof.html"]

for fname in files:
    fpath = os.path.join(website_dir, fname)
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Top navbar update
    if '<li><a href="/docs">Docs</a></li>' not in content:
        content = content.replace(
            '<li><a href="/proof">Proof</a></li>',
            '<li><a href="/proof">Proof</a></li>\n        <li><a href="/docs">Docs</a></li>'
        )
    
    # Footer update
    if '<a href="/docs">Docs</a>' not in content:
        content = content.replace(
            '<li><a href="/pricing">Pricing</a></li>',
            '<li><a href="/pricing">Pricing</a></li>\n            <li><a href="/docs">Docs & API</a></li>'
        )
        
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)

# Update sitemap
sitemap_path = os.path.join(website_dir, "sitemap.xml")
with open(sitemap_path, "r", encoding="utf-8") as f:
    sitemap = f.read()

if "https://aiguardian.dev/docs" not in sitemap:
    sitemap = sitemap.replace(
        "</urlset>",
        "  <url>\n    <loc>https://aiguardian.dev/docs</loc>\n    <lastmod>2026-08-29</lastmod>\n    <priority>0.9</priority>\n  </url>\n</urlset>"
    )

with open(sitemap_path, "w", encoding="utf-8") as f:
    f.write(sitemap)

print("Nav links and sitemap updated with /docs.")
