"""In-process inference using public weights and ML libraries, no model server.

Missing weights, corrupted data, context overflow, or malformed output are
failures. The existing typed judge parser and decision gates remain authoritative.
"""
import hashlib
import json
import os
import threading
from pathlib import Path

_lock=threading.Lock()
_model=None
_tokenizer=None


def ready():return _model is not None and _tokenizer is not None


def _load():
    global _model,_tokenizer
    if ready():return
    import torch
    from transformers import AutoTokenizer,AutoModelForCausalLM
    root=Path(os.getenv('LOCAL_JUDGE_PATH',str(Path(__file__).resolve().parents[1]/'models/local-judge')))
    manifest_path=root.parent/'judge-manifest.json'
    manifest=json.loads(manifest_path.read_text())
    if manifest.get('revision')!='7ae557604adf67be50417f59c2c2f167def9a775':
        raise ValueError('unsupported local judge revision')
    for name,entry in manifest['files'].items():
        if Path(name).name!=name:raise ValueError('invalid model manifest path')
        digest=hashlib.sha256()
        with (root/name).open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
        if digest.hexdigest()!=entry['sha256']:raise ValueError('local judge checksum mismatch')
    torch.set_num_threads(max(1,min(4,int(os.getenv('LOCAL_JUDGE_THREADS','2')))))
    tokenizer=AutoTokenizer.from_pretrained(root,local_files_only=True,trust_remote_code=False)
    model=AutoModelForCausalLM.from_pretrained(root,local_files_only=True,trust_remote_code=False,
                                             use_safetensors=True,torch_dtype=torch.float32)
    model.eval();_tokenizer=tokenizer;_model=model


def warm():
    with _lock:_load()


def generate(prompt,system):
    import torch
    with _lock:
        _load()
        messages=([{'role':'system','content':system}] if system else [])+[{'role':'user','content':prompt}]
        text=_tokenizer.apply_chat_template(messages,tokenize=False,add_generation_prompt=True)
        inputs=_tokenizer(text,return_tensors='pt')
        if inputs['input_ids'].shape[-1]>2048:raise ValueError('local judge input exceeds context budget')
        with torch.inference_mode():
            output=_model.generate(**inputs,max_new_tokens=192,max_time=55,do_sample=False,
                                   pad_token_id=_tokenizer.eos_token_id)
        return _tokenizer.decode(output[0,inputs['input_ids'].shape[-1]:],skip_special_tokens=True)
