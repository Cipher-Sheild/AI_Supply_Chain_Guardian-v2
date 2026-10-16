"""Build portable stdlib-only client bundles; the scanner server stays separate."""
from pathlib import Path
import tempfile
import zipapp

ROOT=Path(__file__).resolve().parents[1]


def main():
    target=ROOT/'dist';target.mkdir(exist_ok=True)
    for output,module in [('guardian.pyz','guardian_cli'),('guardian-lsp.pyz','guardian_lsp')]:
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ['guardian_cli','guardian_lsp','guardian_http']:
                (root/f'{name}.py').write_bytes((ROOT/'scripts'/f'{name}.py').read_bytes())
            (root/'__main__.py').write_text(f'import sys\nfrom {module} import main\nsys.exit(main())\n')
            zipapp.create_archive(root,target=target/output,interpreter='/usr/bin/env python3',compressed=True)
            (target/output).chmod(0o755)
        print(target/output)


if __name__=='__main__':main()
