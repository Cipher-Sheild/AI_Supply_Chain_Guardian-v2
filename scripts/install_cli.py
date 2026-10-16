"""Install Guardian's portable CLI and LSP client for the current user."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from build_cli import main as build

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=Path.home()/'.local/bin')
    args=parser.parse_args();target=args.directory.resolve();target.mkdir(parents=True,exist_ok=True)
    manifest=target/'.guardian-install.json'
    old=json.loads(manifest.read_text()) if manifest.exists() else {}
    build();installed={}
    for name,artifact in [('guardian','guardian.pyz'),('guardian-lsp','guardian-lsp.pyz')]:
        path=target/name
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()!=old.get(name):
            raise ValueError('Refusing to overwrite an unrelated or modified '+str(path))
        raw=(ROOT/'dist'/artifact).read_bytes();temporary=target/(name+'.tmp')
        temporary.write_bytes(raw);temporary.chmod(0o755);os.replace(temporary,path)
        installed[name]=hashlib.sha256(raw).hexdigest()
    manifest.write_text(json.dumps(installed,indent=2)+'\n')
    print('Installed:',target/'guardian','and',target/'guardian-lsp')


if __name__=='__main__':main()
