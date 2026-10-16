#!/usr/bin/env python3
"""Create one isolated local runtime from all direct requirements.
CPU PyTorch is installed first. Docker retains separate environments per service.
"""
import argparse,subprocess,sys,venv
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--path',type=Path,default=ROOT/'.data/venv');args=parser.parse_args()
    venv.EnvBuilder(with_pip=True).create(args.path)
    python=args.path/'bin/python'
    subprocess.run([str(python),'-m','pip','install','torch==2.5.1+cpu','--index-url','https://download.pytorch.org/whl/cpu'],check=True)
    requirements=set()
    for path in (ROOT/'services').glob('*/requirements.txt'):
        for line in path.read_text().splitlines():
            if line.strip() and not line.startswith('#') and not line.startswith('torch=='):requirements.add(line.strip())
    # Pin the training stack as well; avoids an unbounded scikit-learn resolver.
    requirements.update((ROOT/'evaluation/trust_model/requirements.txt').read_text().splitlines())
    requirements.update((ROOT/'scripts/requirements.txt').read_text().splitlines())
    generated=args.path.parent/'runtime-requirements.txt';generated.write_text('\n'.join(sorted(requirements))+'\n')
    subprocess.run([str(python),'-m','pip','install','-r',str(generated)],check=True)
    subprocess.run([str(python),'-m','pip','check'],check=True)
    subprocess.run([str(python),str(ROOT/'scripts/download_embedding_model.py')],check=True)
    subprocess.run([str(python),str(ROOT/'scripts/download_judge_model.py')],check=True)
    subprocess.run(['npm','ci','--prefix',str(ROOT/'frontend')],check=True)
    subprocess.run(['npm','ci','--prefix',str(ROOT/'integrations/vscode')],check=True)
    subprocess.run(['npm','run','build','--prefix',str(ROOT/'integrations/vscode')],check=True)
    print('Runtime ready. Guardian Docker/license scanners need no external scanner installations; use scripts/run_local.py --python',python)
if __name__=='__main__':main()
