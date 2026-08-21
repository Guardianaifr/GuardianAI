import glob
import os
for fpath in glob.glob('**/*.md', recursive=True):
    if 'node_modules' in fpath or '.git' in fpath:
        continue
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        modified = False
        if 'Output Structural Assurance' in content:
            content = content.replace('Output Structural Assurance', 'Output Structural Assurance (Opt-In / Disabled by Default)')
            modified = True
            
        if modified:
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(content)
    except Exception:
        pass
