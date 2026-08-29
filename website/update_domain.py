import os
import re

domain = 'https://aiguardian.dev/'
domain_no_slash = 'https://aiguardian.dev'
website_dir = r'f:/Saas/guardianai-basic-launch/website'

for filename in ['sitemap.xml', 'robots.txt', 'README.md']:
    filepath = os.path.join(website_dir, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    content = content.replace('https://guardianai.example/', domain)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

html_files = ['index.html', 'how-it-works.html', 'pricing.html', 'proof.html']
for filename in html_files:
    filepath = os.path.join(website_dir, filename)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # insert canonical and og:url before </head>
    url_path = domain if filename == 'index.html' else domain + filename
    
    if '<link rel=\"canonical\"' not in content:
        insert_str = f'  <link rel=\"canonical\" href=\"{url_path}\">\n  <meta property=\"og:url\" content=\"{url_path}\">\n'
        content = content.replace('</head>', f'{insert_str}</head>')
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
