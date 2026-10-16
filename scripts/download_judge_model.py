"""Download pinned public model data for in-process Guardian judging."""
import hashlib
import json
from pathlib import Path
from huggingface_hub import snapshot_download

ROOT=Path(__file__).resolve().parents[1]
REPO='Qwen/Qwen2.5-0.5B-Instruct'
REVISION='7ae557604adf67be50417f59c2c2f167def9a775'


def main():
    target=ROOT/'services/prompt_injection/models/local-judge'
    snapshot_download(REPO,revision=REVISION,local_dir=str(target),
        allow_patterns=['*.json','*.safetensors','merges.txt','vocab.json','README.md','LICENSE'])
    files={}
    for path in sorted(target.iterdir()):
        if path.is_file():
            digest=hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
            files[path.name]={'sha256':digest.hexdigest(),'bytes':path.stat().st_size}
    (target.parent/'judge-manifest.json').write_text(json.dumps({'repository':REPO,'revision':REVISION,'files':files},indent=2)+'\n')
    print('Pinned local judge weights and checksums prepared.')


if __name__=='__main__':main()
