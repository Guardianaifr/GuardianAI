import os
import yaml
import subprocess
from pathlib import Path

ROOT = Path(os.getcwd())
config_dir = ROOT / "guardian" / "config"
test_config_path = ROOT / "test_provenance_config.yaml"
manifest_path = ROOT / "fake_manifest.json"

# Load the base config to use as a template
with open(config_dir / "config.yaml", "r") as f:
    base_config = yaml.safe_load(f)

print("=== TEST CASE 1: Manifest Configured but Missing ===")
base_config["hardening"] = {"model_manifest_path": str(manifest_path)}
with open(test_config_path, "w") as f:
    yaml.safe_dump(base_config, f)

# Make sure manifest doesn't exist
if manifest_path.exists():
    manifest_path.unlink()

env = os.environ.copy()
env["PYTHONPATH"] = str(ROOT)
env["GUARDIAN_CONFIG"] = str(test_config_path)

proc1 = subprocess.run(["python", "guardian/main.py"], env=env, capture_output=True, text=True)
print(f"Exit Code: {proc1.returncode}")
for line in proc1.stderr.splitlines():
    if "HardeningProvenance" in line:
        print(line)

print("\n=== TEST CASE 2: Manifest Exists but Hash Mismatches ===")
import json
# Create manifest pointing to README.md but with a fake hash
with open(manifest_path, "w") as f:
    json.dump({"README.md": "fakehash123"}, f)

proc2 = subprocess.run(["python", "guardian/main.py"], env=env, capture_output=True, text=True)
print(f"Exit Code: {proc2.returncode}")
for line in proc2.stderr.splitlines():
    if "HardeningProvenance" in line:
        print(line)

# Clean up
test_config_path.unlink()
manifest_path.unlink()
