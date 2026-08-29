import os
import re

website_dir = r"f:/Saas/guardianai-basic-launch/website"

files_to_update = ["index.html", "how-it-works.html", "pricing.html", "proof.html"]

replacements = [
    # Full domain canonicals / og:urls
    (r"https://aiguardian.dev/index.html", "https://aiguardian.dev/"),
    (r"https://aiguardian.dev/how-it-works.html", "https://aiguardian.dev/how-it-works"),
    (r"https://aiguardian.dev/pricing.html", "https://aiguardian.dev/pricing"),
    (r"https://aiguardian.dev/proof.html", "https://aiguardian.dev/proof"),
    
    # Internal href links with anchors or exact matches
    (r'href="index\.html#', 'href="/#'),
    (r'href="index\.html"', 'href="/"'),
    (r'href="how-it-works\.html#', 'href="/how-it-works#'),
    (r'href="how-it-works\.html"', 'href="/how-it-works"'),
    (r'href="pricing\.html#', 'href="/pricing#'),
    (r'href="pricing\.html"', 'href="/pricing"'),
    (r'href="proof\.html#', 'href="/proof#'),
    (r'href="proof\.html"', 'href="/proof"'),
]

for filename in files_to_update:
    path = os.path.join(website_dir, filename)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    for old, new in replacements:
        content = re.sub(old, new, content)
        
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

# Update sitemap.xml
sitemap_path = os.path.join(website_dir, "sitemap.xml")
with open(sitemap_path, "r", encoding="utf-8") as f:
    sitemap = f.read()

sitemap = sitemap.replace("https://aiguardian.dev/how-it-works.html", "https://aiguardian.dev/how-it-works")
sitemap = sitemap.replace("https://aiguardian.dev/pricing.html", "https://aiguardian.dev/pricing")
sitemap = sitemap.replace("https://aiguardian.dev/proof.html", "https://aiguardian.dev/proof")

with open(sitemap_path, "w", encoding="utf-8") as f:
    f.write(sitemap)

print("HTML and sitemap clean URLs applied successfully.")
