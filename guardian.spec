# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from PyInstaller.utils.hooks import collect_all, copy_metadata

block_cipher = None

# Collecting complex dependencies
datas = []
binaries = []
hiddenimports = []

# --- 1. Streamlit ---
# Streamlit needs 'streamlit' data and metadata
tmp_ret = collect_all('streamlit')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
datas += copy_metadata('streamlit')

# --- 2. Uvicorn/FastAPI ---
datas += copy_metadata('uvicorn')
datas += copy_metadata('fastapi')
hiddenimports += ['uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http']

# --- 3. Presidio ---
datas += copy_metadata('presidio_analyzer')
datas += copy_metadata('presidio_anonymizer')
# Collect NLP Engine (Spacy)
tmp_ret = collect_all('spacy')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
# Explicitly handle en_core_web_lg (assuming default install)
try:
    import en_core_web_lg
    model_path = os.path.dirname(en_core_web_lg.__file__)
    datas += [(model_path, 'en_core_web_lg')]
    hiddenimports += ['en_core_web_lg']
except ImportError:
    print("WARNING: en_core_web_lg not found. Executable may fail PII redaction.")

# --- 4. Application Files ---
# Include config directory (relative to project root)
datas += [('guardian/config', 'guardian/config')]
# Include dashboard app
datas += [('dashboard', 'dashboard')]

a = Analysis(
    ['guardian_launcher.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports + [
        'presidio_analyzer.nlp_engine.spacy_nlp_engine', # Ensure this is bundled
        'presidio_anonymizer.operators.replace',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='GuardianAI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True, # Keep console open for logs (User can see monitoring)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='GuardianAI',
)
