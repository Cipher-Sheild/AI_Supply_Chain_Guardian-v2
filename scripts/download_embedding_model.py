#!/usr/bin/env python3
"""Download the pinned embedding snapshot into the project; no Git secrets."""
import json,shutil,hashlib
from pathlib import Path
from huggingface_hub import snapshot_download
ROOT=Path(__file__).resolve().parents[1]
REVISION='1110a243fdf4706b3f48f1d95db1a4f5529b4d41'
def main():
    source=Path(snapshot_download('sentence-transformers/all-MiniLM-L6-v2',revision=REVISION,allow_patterns=['*.json','*.txt','*.safetensors','1_Pooling/*']))
    target=ROOT/'services/prompt_injection/models/minilm'
    shutil.copytree(source,target,dirs_exist_ok=True)
    metadata={'repo':'sentence-transformers/all-MiniLM-L6-v2','revision':REVISION,'files':{str(p.relative_to(target)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.rglob('*')) if p.is_file()}}
    (target.parent/'embedding-manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print('Pinned embedding snapshot copied to',target)
if __name__=='__main__':main()
