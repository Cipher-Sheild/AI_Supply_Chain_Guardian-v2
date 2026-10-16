"""Generate/check standalone contract copies; no cross-service imports."""
from pathlib import Path
import argparse
root = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(); p.add_argument("--check", action="store_true"); args = p.parse_args()
mismatches=[]
for service in sorted((root/"services").iterdir()):
    if not (service/"app").is_dir(): continue
    for source, target in [("v1.py","contract.py"),("capabilities.json","capabilities.json"),("capabilities.py","capabilities.py")]:
        data=(root/"contracts"/source).read_bytes(); out=service/"app"/target
        if args.check:
            if not out.exists() or out.read_bytes()!=data: mismatches.append(str(out.relative_to(root)))
        else: out.write_bytes(data)
if mismatches: raise SystemExit("Contract drift: " + ", ".join(mismatches))
print("Contract copies verified" if args.check else "Contract copies generated")
