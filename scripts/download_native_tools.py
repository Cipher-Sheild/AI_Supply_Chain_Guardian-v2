#!/usr/bin/env python3
"""Obtain pinned Linux/x86_64 tools in the project, checking release checksums.
Existing matching host tools are copied and hashed (not claimed release-attested).
"""
import hashlib,json,platform,re,shutil,subprocess,tarfile,tempfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'.tools/bin'
def get(url):
    with urllib.request.urlopen(url,timeout=90) as response:return response.read()
def checksum(text,name):
    for line in text.decode().splitlines():
        fields=line.split()
        if len(fields)>=2 and fields[-1].lstrip('*')==name:return fields[0]
    raise ValueError('release checksum missing '+name)
def main():
    if platform.system()!='Linux' or platform.machine() not in {'x86_64','AMD64'}:raise SystemExit('Use platform packages on non-Linux/x86_64 hosts.')
    OUT.mkdir(parents=True,exist_ok=True);report={}
    for tool,version in [('hadolint','2.15.1'),('trivy','0.74.0')]:
        target=OUT/tool;existing=shutil.which(tool)
        if existing and version in subprocess.check_output([existing,'--version'],text=True):
            if Path(existing).resolve()!=target.resolve():shutil.copy2(existing,target)
            source='existing matching host tool; hash recorded, upstream checksum not independently checked'
        else:
            if tool=='hadolint':
                name='hadolint-Linux-x86_64';base=f'https://github.com/hadolint/hadolint/releases/download/v{version}/'
                data=get(base+name);expected=checksum(get(base+name+'.sha256'),name)
                if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Hadolint checksum mismatch')
                target.write_bytes(data)
            else:
                name=f'trivy_{version}_Linux-64bit.tar.gz';base=f'https://github.com/aquasecurity/trivy/releases/download/v{version}/'
                data=get(base+name);expected=checksum(get(base+f'trivy_{version}_checksums.txt'),name)
                if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Trivy checksum mismatch')
                with tempfile.NamedTemporaryFile(suffix='.tar.gz') as file:
                    file.write(data);file.flush()
                    with tarfile.open(file.name) as archive:
                        member=archive.getmember('trivy')
                        if not member.isfile():raise ValueError('invalid Trivy archive member')
                        target.write_bytes(archive.extractfile(member).read())
            source='official release HTTPS download, release checksum matched'
        target.chmod(0o755)
        report[tool]={'version':version,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'source':source}
    (OUT.parent/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Pinned native tools available in',OUT)
if __name__=='__main__':main()
