#!/usr/bin/env python3
"""Package local source for a new repository; excludes history/secrets/runtime data."""
import gzip,hashlib,io,json,re,subprocess,tarfile,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def configured_secrets():
    values=set()
    example_values={line.partition('=')[0]:line.partition('=')[2].strip().strip('\"\'')
                    for line in (ROOT/'.env.example').read_text().splitlines() if '=' in line}
    for path in (ROOT/'.env',ROOT/'.data/production-pass/compose.env'):
        if not path.is_file():continue
        for line in path.read_text().splitlines():
            key,separator,value=line.partition('=')
            if separator and re.search(r'(KEY|TOKEN|PASSWORD|SECRET)$',key.strip()):
                value=value.strip().strip('\"\'')
                # Public example defaults are not private credentials. The deployed
                # configuration is still checked even if it reused such a default.
                if path==ROOT/'.env' and value in example_values.values():continue
                if len(value)>=8:values.add(value.encode())
    return values

def verify_package_input(name,data,secrets):
    blobs=[data]
    if name.endswith('.vsix'):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            blobs.extend(archive.read(member) for member in archive.namelist() if not member.endswith('/'))
    if any(secret in blob for blob in blobs for secret in secrets):
        raise ValueError(f'Configured private credential found in package input: {name}')
    detector_fixture=name in {'services/secret_detection/tests/sample_secrets_flat.py',
                              'services/secret_detection/tests/sample_secrets_realistic.py'}
    if not detector_fixture and any(re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{64,}-----END ',blob) for blob in blobs):
        raise ValueError(f'Private key material found in package input: {name}')

def main():
    out=ROOT/'dist';out.mkdir(exist_ok=True)
    files=set(subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=ROOT,text=True).splitlines())
    files.add('integrations/vscode/guardian.vsix')
    allowed=[]
    for name in sorted(files):
        path=ROOT/name
        if not path.is_file() or path.is_symlink():continue
        if any(part in {'.git','.data','.aws','.codex','.agents','node_modules','dist','__pycache__'} for part in Path(name).parts):continue
        if Path(name).name=='.env' or name.startswith('services/prompt_injection/models/minilm/'):continue
        allowed.append((name,path))
    secrets=configured_secrets()
    for name,path in allowed:verify_package_input(name,path.read_bytes(),secrets)
    target=out/'guardian-final-source.tar.gz'
    with target.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w') as archive:
        for name,path in allowed:
            data=path.read_bytes();info=tarfile.TarInfo('ai-supply-chain-guardian/'+name)
            info.size=len(data);info.mode=0o755 if path.stat().st_mode&0o111 else 0o644;info.mtime=0
            archive.addfile(info,io.BytesIO(data))
    manifest={'source_files':len(allowed),'archive_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'excluded':'Git history, .env, private configuration, .data, node_modules, downloaded embedding/native binaries; setup scripts restore dependencies','includes':'source, docs, corpus/labels/results, learned model/metadata and packaged VSIX'}
    manifest['privacy_check']={'configured_private_credentials_including_compressed_vsix':'passed',
                               'public_detector_key_fixtures':'Two named secret_detection sample fixtures retained for scanner regression tests'}
    verification=ROOT/'evaluation/production-pass/verification.json'
    if verification.exists():
        report=json.loads(verification.read_text())
        manifest['verification']='evaluation/production-pass/verification.json'
        manifest['complete_production_release_approved']=report.get('complete_production_release_approved',False)
        manifest['prompt_injection_tested']=report.get('prompt_injection_tested',False)
        manifest['release_status']='Operational demo validated; security production release blocked by recorded accuracy and coverage gaps' if report.get('prompt_injection_tested') else 'Non-prompt-injection demo verified; complete production release pending stated gates'
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Local source bundle:',target,'files',len(allowed),'bytes',target.stat().st_size)
if __name__=='__main__':main()
