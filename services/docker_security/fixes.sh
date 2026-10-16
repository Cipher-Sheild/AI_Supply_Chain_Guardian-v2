#!/bin/bash
set -e
cd ~/ai-supply-chain-guardian/services/docker_security

echo "=== 1. Remove debug prints from trivy_config.py ==="
python3 - <<'PYEOF'
import re

path = "app/engines/trivy_config.py"
with open(path, "r") as f:
    content = f.read()

# Remove the three debug print lines added earlier
debug_block = '''                stderr_text = proc.stderr.decode("utf-8", errors="replace")
                print(f"[DEBUG trivy_config] HOME={os.environ.get('HOME')}", flush=True)
                print(f"[DEBUG trivy_config] cmd={cmd}", flush=True)
                print(f"[DEBUG trivy_config] stderr:\\n{stderr_text}", flush=True)

'''
if debug_block in content:
    content = content.replace(debug_block, "")
    print("Removed debug print block.")
else:
    print("WARNING: exact debug block not found — check trivy_config.py manually.")

with open(path, "w") as f:
    f.write(content)
PYEOF

echo ""
echo "=== 2. Add --skip-check-update to trivy_config.py (if not already present) ==="
python3 - <<'PYEOF'
path = "app/engines/trivy_config.py"
with open(path, "r") as f:
    content = f.read()

old = 'cmd = [self.binary_path, "config", "--format", "json", target_path]'
new = 'cmd = [self.binary_path, "config", "--format", "json", "--skip-check-update", target_path]'

if "--skip-check-update" in content:
    print("trivy_config.py already has --skip-check-update — skipping.")
elif old in content:
    content = content.replace(old, new)
    with open(path, "w") as f:
        f.write(content)
    print("Added --skip-check-update to trivy_config.py")
else:
    print("WARNING: expected cmd line not found in trivy_config.py — check manually.")
PYEOF

echo ""
echo "=== 3. Show trivy_image.py so we can check/add the same flag ==="
cat app/engines/trivy_image.py
